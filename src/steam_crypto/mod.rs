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
#[derive(Debug, Clone)]
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

// Who knows if this works, I need to check
pub fn symetric_encrypt(input: &[u8], key: SessionKey, iv: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut aes_iv = openssl::symm::Crypter::new(
	openssl::symm::Cipher::aes_256_ecb(),
	openssl::symm::Mode::Encrypt,
	&key.raw,
	Some("".as_bytes()))?;
    aes_iv.pad(false);
    let mut iv_output = vec![0; iv.len() + openssl::symm::Cipher::aes_256_ecb().block_size()];
    let mut iv_len = aes_iv.update(&iv, &mut iv_output)?;
    //iv_output.truncate(iv_len);
    iv_len += aes_iv.finalize(&mut iv_output[iv_len..])?;

    let mut aes_data = openssl::symm::Crypter::new(
	openssl::symm::Cipher::aes_256_cbc(),
	openssl::symm::Mode::Encrypt,
	&key.raw,
	Some(&iv))?;
    let mut data_output = vec![0; input.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
    let mut data_len = aes_data.update(&input, &mut data_output)?;
    data_len += aes_data.finalize(&mut data_output[data_len..])?;

    Ok([&iv_output[0..iv_len] as &[u8], &data_output[0..data_len]].concat().to_vec())
}

pub fn symetric_hmac_iv(input: &[u8], session_key: SessionKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut random = [0u8; 3];
    rand::thread_rng().fill_bytes(&mut random);
    
    let hmac = hmacsha1::hmac_sha1(&session_key.raw[0..16], &[&random as &[u8], &input].concat());

    let iv = [&hmac[0..16-3], &random].concat().to_vec();

    Ok(symetric_encrypt(input, session_key, iv)?)
}

pub fn symmetric_decrypt(input: &[u8], session_key: SessionKey, check_hmac: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut aes_iv = openssl::symm::Crypter::new(
	openssl::symm::Cipher::aes_256_ecb(),
	openssl::symm::Mode::Decrypt,
	&session_key.raw,
	Some("".as_bytes()))?;
    aes_iv.pad(false);
    let mut iv = vec![0; 16 + openssl::symm::Cipher::aes_256_ecb().block_size()];
    let mut iv_len = aes_iv.update(&input[0..16], &mut iv)?;
    iv_len += aes_iv.finalize(&mut iv[iv_len..])?;
    iv.truncate(iv_len);

    let mut aes_data = openssl::symm::Crypter::new(
	openssl::symm::Cipher::aes_256_cbc(),
	openssl::symm::Mode::Decrypt,
	&session_key.raw,
	Some(&iv))?;
    let mut data_output = vec![0; input.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
    let mut data_len = aes_data.update(&input[16..], &mut data_output)?;
    data_len += aes_data.finalize(&mut data_output[data_len..])?;
    data_output.truncate(data_len);

    if check_hmac {
	let remote_partial_hmac = &iv[0..iv.len()-3];
	let random = &iv[iv.len()-3..iv.len()];

	let hmac = hmacsha1::hmac_sha1(&session_key.raw[0..16], &[random, &data_output].concat());

	if &hmac[0..remote_partial_hmac.len()] != remote_partial_hmac {
	    panic!("Wrong hmac");
	}
    }

    Ok(data_output)
}
