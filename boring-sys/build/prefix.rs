use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use bindgen::callbacks::{ItemInfo, ParseCallbacks};

pub(crate) const PREFIX: &str = "B2_RUST_4_15_15";

pub(crate) fn validate_build(
    enabled: bool,
    fips: bool,
    precompiled: bool,
    external_source: bool,
) -> io::Result<()> {
    if enabled && (fips || precompiled || external_source) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Symbol prefixing requires the bundled non-FIPS source without precompiled archives.",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectFormat {
    Elf,
    MachO,
    Pe,
}

impl ObjectFormat {
    pub(crate) fn from_target_os(target_os: &str) -> io::Result<Self> {
        match target_os {
            "macos" | "ios" => Ok(Self::MachO),
            "windows" => Ok(Self::Pe),
            "linux" | "android" | "freebsd" | "openbsd" | "netbsd" | "dragonfly" | "solaris"
            | "illumos" | "haiku" | "hurd" => Ok(Self::Elf),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Symbol prefixing does not support the target operating system {target_os}."
                ),
            )),
        }
    }

    fn argument(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Pe => "pe",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SymbolNamespace {
    symbols: BTreeSet<String>,
    linker_underscore: bool,
}

impl SymbolNamespace {
    pub(crate) fn new(symbols: BTreeSet<String>, format: ObjectFormat, target_arch: &str) -> Self {
        Self {
            symbols,
            linker_underscore: format == ObjectFormat::MachO
                || (format == ObjectFormat::Pe && target_arch == "x86"),
        }
    }

    pub(crate) fn verify(&self, exported: &BTreeSet<String>) -> io::Result<()> {
        if exported
            .iter()
            .any(|symbol| !symbol.starts_with(&format!("{PREFIX}_")))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The BoringSSL archive still exports unprefixed C symbols.",
            ));
        }
        for symbol in &self.symbols {
            if !exported.contains(&format!("{PREFIX}_{symbol}")) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("The BoringSSL archive is missing the prefixed symbol {symbol}."),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn link_name(&self, name: &str) -> Option<String> {
        self.symbols.contains(name).then(|| {
            let leading = if self.linker_underscore { "_" } else { "" };
            format!("{leading}{PREFIX}_{name}")
        })
    }
}

impl ParseCallbacks for SymbolNamespace {
    fn generated_link_name_override(&self, item: ItemInfo<'_>) -> Option<String> {
        self.link_name(item.name)
    }
}

pub(crate) fn parse_symbols(output: &str) -> io::Result<BTreeSet<String>> {
    let mut symbols = BTreeSet::new();
    for symbol in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut bytes = symbol.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("The archive exports an invalid C symbol identifier: {symbol}."),
            ));
        }
        symbols.insert(symbol.to_owned());
    }
    if symbols.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The BoringSSL archives do not export any C symbols.",
        ));
    }
    Ok(symbols)
}

pub(crate) fn find_archive(build_path: &Path, file_name: &str) -> io::Result<PathBuf> {
    let mut found = None;
    let mut pending = vec![build_path.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_name() == file_name {
                if found.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("More than one BoringSSL archive is named {file_name}."),
                    ));
                }
                found = Some(entry.path());
            }
        }
    }
    found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("The BoringSSL build does not contain {file_name}."),
        )
    })
}

pub(crate) fn read_symbols(
    source_path: &Path,
    build_path: &Path,
    format: ObjectFormat,
) -> io::Result<BTreeSet<String>> {
    let (crypto, ssl) = match format {
        ObjectFormat::Pe => ("crypto.lib", "ssl.lib"),
        ObjectFormat::Elf | ObjectFormat::MachO => ("libcrypto.a", "libssl.a"),
    };
    let build_path = build_path.join("build");
    let source_root = source_path.join("src").canonicalize()?;
    let output = Command::new("go")
        .args([
            "run",
            "./util/read_symbols.go",
            "-obj-file-format",
            format.argument(),
        ])
        .arg(find_archive(&build_path, crypto)?)
        .arg(find_archive(&build_path, ssl)?)
        .current_dir(source_root)
        .env("GOWORK", "off")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "The BoringSSL symbol reader failed: {}",
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    parse_symbols(
        std::str::from_utf8(&output.stdout)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
    )
}

pub(crate) fn generate_headers(
    source_path: &Path,
    include_path: &Path,
    symbols: &BTreeSet<String>,
) -> io::Result<()> {
    let source_root = source_path.join("src").canonicalize()?;
    std::fs::create_dir_all(include_path)?;
    let symbol_file = include_path.join("symbols.txt");
    std::fs::write(
        &symbol_file,
        symbols
            .iter()
            .map(|symbol| format!("{symbol}\n"))
            .collect::<String>(),
    )?;
    let output = Command::new("go")
        .args(["run", "./util/make_prefix_headers.go", "-out"])
        .arg(include_path)
        .arg(symbol_file)
        .current_dir(source_root)
        .env("GOWORK", "off")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "The BoringSSL prefix header generator failed: {}",
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    Ok(())
}
