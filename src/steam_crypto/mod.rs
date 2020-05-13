use openssl::rsa::{Padding, Rsa};

use rand::RngCore;

/// The RSA public key used by CM Sockets to do primary encryption (Session Keys)
pub const STEAM_PUB: &str = r#"-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
6WOiu4gZKODnFMBCiQIBEQ==
-----END PUBLIC KEY-----"#;

/// A datastructure for storing all versions of the session key required
/// to enable channel encryption with the CM Socket.
#[derive(Debug)]
pub struct SessionKey {
    /// RSA encrypted (PKCS1_OAEP) copy of the session key
    pub encrypted: Vec<u8>,
    /// The session key, which is 32 random bytes
    pub raw: Vec<u8>,
}

impl SessionKey {
    /// Generate a session key for a CM Socket.
    ///
    /// The generate function takes in nonce, given by the CM Socket
    /// to encrypt a session key (random 32 bytes) concatenated with nonce.
    pub fn generate(nonce: [u8; 16]) -> Result<SessionKey, Box<dyn std::error::Error>> {
        // Generate the session key by using 32 random bytes using thread_rng
        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);

        // Load the RSA key to encrypt the session key with
        let rsa = Rsa::public_key_from_pem(STEAM_PUB.as_bytes())?;

        // Encrypt the session key with RSA and PKCS1_OAEP padding
        let mut buf = vec![0; rsa.size() as usize];
        rsa.public_encrypt(
            &[&session_key as &[u8], &nonce as &[u8]].concat(),
            &mut buf,
            Padding::PKCS1_OAEP,
        )
        .unwrap();

        Ok(SessionKey {
            raw: session_key.to_vec(),
            encrypted: buf,
        })
    }
}
