use std::net::{SocketAddr, TcpStream};

use std::io::Cursor;
use std::io::{Read, Write};

use std::convert::TryInto;

pub struct CMReader {
    cursor: Cursor<Vec<u8>>,
}

impl CMReader {
    pub fn byte(&mut self) -> Result<u8, Box<dyn std::error::Error>> {
        let mut buf = [0; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    pub fn bytes(&mut self, num: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = vec![];
        for _ in 0..num {
            bytes.push(self.byte()?);
        }
        Ok(bytes)
    }

    pub fn uint32(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let mut buf = [0; 4];
        self.cursor.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf.try_into()?))
    }

    pub fn uint64(&mut self) -> Result<u64, Box<dyn std::error::Error>> {
        let mut buf = [0; 8];
        self.cursor.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf.try_into()?))
    }

    pub fn inner(&mut self) -> Vec<u8> {
	self.cursor.clone().into_inner().clone()
    }

    pub fn new(inner: Vec<u8>) -> CMReader {
        CMReader {
            cursor: Cursor::new(inner),
        }
    }
}

pub struct CMWriter {
    inner: Vec<u8>,
}

impl CMWriter {
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut CMWriter {
        self.inner.extend(bytes);
        self
    }

    pub fn uint32(&mut self, int: u32) -> &mut CMWriter {
        self.bytes(&int.to_le_bytes());
        self
    }

    pub fn uint64(&mut self, int: u64) -> &mut CMWriter {
        self.bytes(&int.to_le_bytes());
        self
    }

    pub fn get_inner(&self) -> Vec<u8> {
        self.inner.clone()
    }

    pub fn with_size(size: usize) -> CMWriter {
        CMWriter {
            inner: Vec::with_capacity(size),
        }
    }

    pub fn new() -> CMWriter {
        CMWriter { inner: vec![] }
    }
}

pub struct CMSocket {
    addr: SocketAddr,
}

impl CMSocket {
    pub fn new(addr: &str) -> Result<CMSocket, Box<dyn std::error::Error>> {
        Ok(CMSocket {
            addr: addr.parse()?,
        })
    }

    fn send_message(
        socket: &mut TcpStream,
        response_header: &[u8],
        response_body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        socket.write_all(
            &[
                &(response_body.len() as u32 + response_header.len() as u32).to_le_bytes()
                    as &[u8],
                "VT01".as_bytes(),
                response_header,
                response_body,
            ]
		.concat(),
        )?;

        Ok(())
    }

    pub fn start_listener(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let socket =
            &mut TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(1000))?;

        let mut message_length = None;
	let mut session_key = None;
	let mut crypted = false;

        loop {
            if message_length.is_none() {
                // Read in basic data required to read a message
                let mut size_raw: [u8; 4] = [0; 4];
                let mut magic_raw: [u8; 4] = [0; 4];
                socket.read(&mut size_raw)?;
                socket.read(&mut magic_raw)?;

                // Check if the magic is correct, abort if not
                if String::from_utf8_lossy(&magic_raw) != "VT01" {
                    println!("Wrong magic: {:#?}", magic_raw);
                    break; // Wrong magic, abort
                } else {
                    println!("Correct magic");
                    message_length = Some(i32::from_le_bytes(size_raw));
                }
            } else {
                // Fetch the data
                let mut data: CMReader = CMReader::new(
                    socket
                        .bytes()
                        .take(message_length.unwrap() as usize)
                        .map(|x| x.unwrap()) // I hate this, but this will have to do
                        .collect(),
                );
		if crypted {
		    println!("Before (decryption): {}", u32::from_le_bytes(data.inner()[0..4].try_into()?));
		    data = CMReader::new(
			crate::steam_crypto::symmetric_decrypt(&data.inner(), session_key.clone().unwrap(), true)?
		    );
		    println!("After (decryption): {}", u32::from_le_bytes(data.inner()[0..4].try_into()?));
		}

		let kind = data.uint32()? & !0x80000000;
		println!("Is protobuf: {}", (kind & 0x80000000) != 0);
		const JOBID_NONE: u64 = 18446744073709551615;
                match kind {
                    1303 => {
                        // Channel encrypt request
                        let target_job_id = data.uint64()?;
                        let source_job_id = data.uint64()?;
                        println!("Target: {}, Source: {}", target_job_id, source_job_id);

                        let protocol = data.uint32()?;
                        let universe = data.uint32()?;
                        let nonce = &data.bytes(16)? as &[u8]; // Used to build the crypto key

                        println!("Protocol: {}", protocol);
                        println!("Universe: {}", universe);

                        let temp_session_key =
                            crate::steam_crypto::SessionKey::generate(nonce.try_into()?)?;

                        let response_body =
                            CMWriter::with_size(4 + 4 + temp_session_key.encrypted.len() + 4 + 4)
                            .uint32(protocol)
                            .uint32(temp_session_key.encrypted.len() as u32)
                            .bytes(&temp_session_key.encrypted)
                            .uint32(crc::crc32::checksum_ieee(&temp_session_key.encrypted) as u32)
                            .uint32(0)
                            .get_inner();

                        let response_header = CMWriter::with_size(4 + 8 + 8)
                            .uint32(1304)
                            .uint64(JOBID_NONE)
                            .uint64(JOBID_NONE)
                            .get_inner();

                        // Send the message
                        CMSocket::send_message(socket, &response_header, &response_body)?;

			session_key = Some(temp_session_key);
                    },
		    1305 => {
			use crate::protos::steammessages::CMsgClientLogon;
			use crate::protos::steammessages::CMsgProtoBufHeader;
			use crate::prost::Message;

			let username = env!("STEAM_USERNAME");
			let password = env!("STEAM_PASSWORD");

			let mut client_logon: CMsgClientLogon = Default::default();
			client_logon.account_name = Some(username.to_string());
			client_logon.password = Some(password.to_string());
			client_logon.should_remember_password = Some(false);
			client_logon.obfuscated_private_ip = Some(crate::protos::steammessages::CMsgIpAddress {ip: Some(crate::protos::steammessages::c_msg_ip_address::Ip::V4(0))});
			client_logon.protocol_version = Some(65580);
			client_logon.supports_rate_limit_response = Some(true);
			client_logon.machine_name = Some("".to_string());
			client_logon.deprecated_10 = Some(6);
			client_logon.client_language = Some("english".to_string());
			client_logon.client_os_type = Some(-203i32 as u32);
			client_logon.anon_user_target_account_name = Some("".to_string());
			client_logon.steamguard_dont_remember_computer = Some(false);
			client_logon.ui_mode = None;
			client_logon.chat_mode = Some(2);
			client_logon.anon_user_target_account_name = Some("".to_string());
			//client_logon.sha_sentryfile = Some(b"null".to_vec());
			client_logon.eresult_sentryfile = Some(0);

			// Hardcoded randoms for now...
			let bb3 = "8909235489275357238953425897809523758907";
			let ff2 = "5980258132958905238905218559032859032855";
			let b3 =  "3422587614819274653481756891374561897345";
			
			// Generate machine id
			let machine_id = CMWriter::new()
			    .bytes(&[0])
			    .bytes(b"MessageObject")
			    .bytes(&[0])
			    .bytes(&[1])
			    .bytes(b"BB3")
			    .bytes(&[0])
			    .bytes(crate::hex::encode(openssl::sha::sha1(bb3.as_bytes())).as_bytes())
			    .bytes(&[0])
			    .bytes(&[1])
			    .bytes(b"FF2")
			    .bytes(&[0])
			    .bytes(crate::hex::encode(openssl::sha::sha1(ff2.as_bytes())).as_bytes())
			    .bytes(&[0])
			    .bytes(&[1])
			    .bytes(b"3B3")
			    .bytes(&[0])
			    .bytes(crate::hex::encode(openssl::sha::sha1(b3.as_bytes())).as_bytes())
			    .bytes(&[0])
			    .bytes(&[8, 8])
			    .get_inner();

			//println!("{:#?}", machine_id);

			client_logon.machine_id = Some(machine_id);

			let mut proto_header: CMsgProtoBufHeader = Default::default();
			proto_header.client_sessionid = Some(0);
			proto_header.jobid_source = Some(JOBID_NONE);
			proto_header.jobid_target = Some(JOBID_NONE);
			proto_header.steamid = Some(76561197960265728);
			//proto_header.client_sessionid = Some(0);

			
			let mut response_header = vec![];
			proto_header.encode(&mut response_header)?;

			let mut response_body = vec![];
			client_logon.encode(&mut response_body)?;
			
			const PROTO_MASK: u32 = 0x80000000;
			let response_encrypted = crate::steam_crypto::symetric_hmac_iv(
			    &[
				&(5514u32 | PROTO_MASK).to_le_bytes() as &[u8],
				&(response_header.len() as u32).to_le_bytes() as &[u8],
				&response_header as &[u8],
				&response_body as &[u8]
			    ].concat(),
			    session_key.clone().unwrap())?;

			println!("Sending login request");
			CMSocket::send_message(socket, &[], &response_encrypted)?;

			crypted = true;
			
		    }
                    _ => println!("Recieved {}", kind),
                }

                message_length = None;
            }
        }

        Ok(())
    }
}
