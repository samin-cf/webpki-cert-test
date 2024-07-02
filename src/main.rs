use rustls::pki_types::UnixTime;
use rustls::RootCertStore;

use webpki::EndEntityCert;
use webpki::{aws_lc_rs as sig_algs, KeyUsage};

fn main() {
    let mut root_store = RootCertStore::empty();

    let mut reader = std::io::BufReader::new(std::fs::File::open("./certs/ca.crt").unwrap());
    root_store.add_parsable_certificates(
        rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
    );

    for server_cert_algorithm in ["sha256", "sha384", "sha512"] {
        let mut reader = std::io::BufReader::new(
            std::fs::File::open(format!("./certs/server_{}.crt", server_cert_algorithm)).unwrap(),
        );
        let server_cert = rustls_pemfile::certs(&mut reader)
            .map(|r| r.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(server_cert.len(), 1);

        let cert = EndEntityCert::try_from(server_cert.first().unwrap()).unwrap();
        match cert.verify_for_usage(
            &[
                sig_algs::ECDSA_P256_SHA256,
                sig_algs::ECDSA_P256_SHA384,
                sig_algs::ECDSA_P384_SHA256,
                sig_algs::ECDSA_P384_SHA384,
                sig_algs::ECDSA_P521_SHA512,
                sig_algs::ED25519,
                sig_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                sig_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                sig_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                sig_algs::RSA_PKCS1_2048_8192_SHA256,
                sig_algs::RSA_PKCS1_2048_8192_SHA384,
                sig_algs::RSA_PKCS1_2048_8192_SHA512,
                sig_algs::RSA_PKCS1_3072_8192_SHA384,
            ],
            &root_store.roots,
            &[],
            UnixTime::now(),
            KeyUsage::server_auth(),
            None,
            None,
        ) {
            Err(err) => {
                println!(
                    "Server certificate signed with ecdsa-with-{} failed to be verified: {:?}",
                    server_cert_algorithm, err
                );
            }
            Ok(_) => {
                println!(
                    "Server certificate signed with ecdsa-with-{} verified successfully",
                    server_cert_algorithm
                );
            }
        }
    }
}
