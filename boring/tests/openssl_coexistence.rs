use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const CERTIFICATE: &[u8] = include_bytes!("../test/cert.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("../test/key.pem");

fn socket(stream: TcpStream) -> TcpStream {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

fn receive_and_reply(stream: &mut (impl Read + Write)) {
    let mut buffer = [0; 4];
    stream.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"ping");
    stream.write_all(b"pong").unwrap();
    stream.flush().unwrap();
}

fn exchange(stream: &mut (impl Read + Write)) {
    stream.write_all(b"ping").unwrap();
    stream.flush().unwrap();
    let mut buffer = [0; 4];
    stream.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"pong");
}

#[test]
fn both_crypto_engines_hash_independently_in_one_process() {
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    for _ in 0..32 {
        let boring = boring2::hash::hash(boring2::hash::MessageDigest::sha256(), b"abc").unwrap();
        let openssl = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), b"abc").unwrap();
        assert_eq!(boring.as_ref(), expected);
        assert_eq!(openssl.as_ref(), expected);
    }
}

#[test]
fn boring_client_connects_to_openssl_server() {
    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&openssl::x509::X509::from_pem(CERTIFICATE).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap())
        .unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut stream = acceptor.accept(socket(stream)).unwrap();
        receive_and_reply(&mut stream);
    });
    let mut connector =
        boring2::ssl::SslConnector::builder(boring2::ssl::SslMethod::tls()).unwrap();
    connector.set_verify(boring2::ssl::SslVerifyMode::NONE);
    let mut stream = connector
        .build()
        .connect("localhost", socket(TcpStream::connect(address).unwrap()))
        .unwrap();
    exchange(&mut stream);
    server.join().unwrap();
}

#[test]
fn openssl_client_connects_to_boring_server() {
    let mut acceptor =
        boring2::ssl::SslAcceptor::mozilla_intermediate(boring2::ssl::SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&boring2::x509::X509::from_pem(CERTIFICATE).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&boring2::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap())
        .unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut stream = acceptor.accept(socket(stream)).unwrap();
        receive_and_reply(&mut stream);
    });
    let mut connector =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let mut stream = connector
        .build()
        .connect("localhost", socket(TcpStream::connect(address).unwrap()))
        .unwrap();
    exchange(&mut stream);
    server.join().unwrap();
}
