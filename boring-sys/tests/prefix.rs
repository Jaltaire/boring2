#[path = "../build/prefix.rs"]
mod prefix;

use std::collections::BTreeSet;
use std::io::ErrorKind;

use prefix::{LibraryNamespace, NativeLibrary, ObjectFormat, SymbolNamespace, PREFIX};

fn symbols(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn incompatible_build_options_are_rejected_only_when_prefixing_is_enabled() {
    for enabled in [false, true] {
        for fips in [false, true] {
            for precompiled in [false, true] {
                for external_source in [false, true] {
                    let result =
                        prefix::validate_build(enabled, fips, precompiled, external_source);
                    if enabled && (fips || precompiled || external_source) {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::Unsupported);
                    } else {
                        result.unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn missing_symbol_tools_and_archives_produce_errors() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        prefix::read_symbols(root.path(), root.path(), ObjectFormat::Elf)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        prefix::generate_headers(
            root.path(),
            &root.path().join("include"),
            &symbols(&["SSL_new"])
        )
        .unwrap_err()
        .kind(),
        ErrorKind::NotFound
    );
    std::fs::create_dir_all(root.path().join("src")).unwrap();
    assert_eq!(
        prefix::generate_headers(
            root.path(),
            &root.path().join("include"),
            &symbols(&["SSL_new"])
        )
        .unwrap_err()
        .kind(),
        ErrorKind::Other
    );
}

#[test]
fn supported_object_formats_are_explicit() {
    for target in ["macos", "ios"] {
        assert_eq!(
            ObjectFormat::from_target_os(target).unwrap(),
            ObjectFormat::MachO
        );
    }
    assert_eq!(
        ObjectFormat::from_target_os("windows").unwrap(),
        ObjectFormat::Pe
    );
    for target in [
        "linux",
        "android",
        "freebsd",
        "openbsd",
        "netbsd",
        "dragonfly",
        "solaris",
        "illumos",
        "haiku",
        "hurd",
    ] {
        assert_eq!(
            ObjectFormat::from_target_os(target).unwrap(),
            ObjectFormat::Elf
        );
    }
    assert_eq!(
        ObjectFormat::from_target_os("unknown").unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn symbol_parsing_is_sorted_and_deduplicated() {
    assert_eq!(
        prefix::parse_symbols("  SSL_new\n\nCRYPTO_init\nSSL_new\n_asm_42\n").unwrap(),
        symbols(&["SSL_new", "CRYPTO_init", "_asm_42"])
    );
    for invalid in [
        "",
        " \n",
        "9symbol",
        "a.b",
        "a-b",
        "a b",
        "nonascii\u{00e9}",
        "SSL_new\n?bad",
    ] {
        assert_eq!(
            prefix::parse_symbols(invalid).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
}

#[test]
fn functions_and_globals_are_bound_to_the_same_namespace() {
    for (format, arch, underscore) in [
        (ObjectFormat::Elf, "x86_64", ""),
        (ObjectFormat::MachO, "aarch64", "_"),
        (ObjectFormat::Pe, "x86", "_"),
        (ObjectFormat::Pe, "x86_64", ""),
    ] {
        let namespace =
            SymbolNamespace::new(symbols(&["SSL_new", "OPENSSL_ia32cap_P"]), format, arch);
        for name in ["SSL_new", "OPENSSL_ia32cap_P"] {
            assert_eq!(
                namespace.link_name(name),
                Some(format!("{underscore}{PREFIX}_{name}"))
            );
        }
        assert_eq!(namespace.link_name("unrelated"), None);
    }
}

#[test]
fn generated_bindings_preserve_rust_names_and_rename_c_symbols() {
    let namespace = SymbolNamespace::new(
        symbols(&["SSL_new", "OPENSSL_ia32cap_P"]),
        ObjectFormat::Elf,
        "x86_64",
    );
    let bindings = bindgen::Builder::default()
        .header_contents(
            "namespace.h",
            "void SSL_new(void); extern int OPENSSL_ia32cap_P; void unrelated(void);",
        )
        .parse_callbacks(Box::new(namespace))
        .generate()
        .unwrap()
        .to_string();
    assert!(
        bindings.contains("pub fn SSL_new"),
        "The original Rust function name must be retained."
    );
    assert!(
        bindings.contains("pub static mut OPENSSL_ia32cap_P"),
        "The original Rust global name must be retained."
    );
    assert!(
        bindings.contains(&format!("{PREFIX}_SSL_new")),
        "The function must link to its namespaced C symbol."
    );
    assert!(
        bindings.contains(&format!("{PREFIX}_OPENSSL_ia32cap_P")),
        "The global must link to its namespaced C symbol."
    );
    assert!(
        !bindings.contains(&format!("{PREFIX}_unrelated")),
        "Unrelated declarations must not acquire a namespace."
    );
}

#[test]
fn symbol_audits_reject_leaks_and_missing_exports() {
    let namespace = SymbolNamespace::new(
        symbols(&["SSL_new", "SSL_free"]),
        ObjectFormat::Elf,
        "x86_64",
    );
    let complete = symbols(&[&format!("{PREFIX}_SSL_new"), &format!("{PREFIX}_SSL_free")]);
    namespace.verify(&complete).unwrap();
    let mut leaking = complete.clone();
    leaking.insert("SSL_new".to_owned());
    assert_eq!(
        namespace.verify(&leaking).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    let mut missing = complete;
    missing.remove(&format!("{PREFIX}_SSL_free"));
    assert_eq!(
        namespace.verify(&missing).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        namespace.verify(&BTreeSet::new()).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn archives_must_be_present_and_unambiguous() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        prefix::find_archive(root.path(), "libssl.a")
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let nested = root.path().join("build/ssl");
    std::fs::create_dir_all(&nested).unwrap();
    let archive = nested.join("libssl.a");
    std::fs::write(&archive, []).unwrap();
    assert_eq!(
        prefix::find_archive(root.path(), "libssl.a").unwrap(),
        archive
    );
    std::fs::write(root.path().join("libssl.a"), []).unwrap();
    assert_eq!(
        prefix::find_archive(root.path(), "libssl.a")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        prefix::find_archive(&root.path().join("absent"), "libssl.a")
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn isolated_archives_have_unique_linker_names_on_every_object_format() {
    for format in [ObjectFormat::Elf, ObjectFormat::MachO, ObjectFormat::Pe] {
        let root = tempfile::tempdir().unwrap();
        for library in NativeLibrary::ALL {
            let directory = root
                .path()
                .join("build")
                .join(library.link_name(LibraryNamespace::Original));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(library.archive_name(format, LibraryNamespace::Original)),
                library.link_name(LibraryNamespace::Original),
            )
            .unwrap();
        }
        let output = prefix::isolate_archives(root.path(), format).unwrap();
        for library in NativeLibrary::ALL {
            assert_ne!(
                library.link_name(LibraryNamespace::Original),
                library.link_name(LibraryNamespace::Isolated)
            );
            assert_eq!(
                std::fs::read_to_string(
                    output.join(library.archive_name(format, LibraryNamespace::Isolated))
                )
                .unwrap(),
                library.link_name(LibraryNamespace::Original),
            );
            assert!(
                !output
                    .join(library.archive_name(format, LibraryNamespace::Original))
                    .exists(),
                "The isolated search directory must not shadow an original TLS archive."
            );
        }
        assert_eq!(std::fs::read_dir(&output).unwrap().count(), 2);
        assert_eq!(
            prefix::isolate_archives(root.path(), format).unwrap(),
            output
        );
    }
}

#[test]
fn isolated_archives_reject_missing_sources_and_unwritable_destinations() {
    let absent = tempfile::tempdir().unwrap();
    assert_eq!(
        prefix::isolate_archives(absent.path(), ObjectFormat::Elf)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    std::fs::create_dir_all(absent.path().join("build")).unwrap();
    std::fs::write(absent.path().join("build/libcrypto.a"), []).unwrap();
    assert_eq!(
        prefix::isolate_archives(absent.path(), ObjectFormat::Elf)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    let blocked = tempfile::tempdir().unwrap();
    std::fs::write(blocked.path().join("namespaced-libraries"), []).unwrap();
    assert_eq!(
        prefix::isolate_archives(blocked.path(), ObjectFormat::Elf)
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );

    let destination = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(destination.path().join("build")).unwrap();
    for library in NativeLibrary::ALL {
        std::fs::write(
            destination
                .path()
                .join("build")
                .join(library.archive_name(ObjectFormat::Elf, LibraryNamespace::Original)),
            [],
        )
        .unwrap();
    }
    std::fs::create_dir_all(
        destination.path().join("namespaced-libraries").join(
            NativeLibrary::Crypto.archive_name(ObjectFormat::Elf, LibraryNamespace::Isolated),
        ),
    )
    .unwrap();
    assert!(prefix::isolate_archives(destination.path(), ObjectFormat::Elf).is_err());
}
