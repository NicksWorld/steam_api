use std::net::{SocketAddr, TcpStream};

use std::io::{Read, Write};

use std::convert::TryInto;

pub struct CMSocket {
    addr: SocketAddr,
}

impl CMSocket {
    pub fn new(addr: &str) -> Result<CMSocket, Box<dyn std::error::Error>> {
        Ok(CMSocket {
            addr: addr.parse()?,
        })
    }

    pub fn start_listener(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let socket =
            &mut TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(1))?;

        let mut message_length = None;

        loop {
            if message_length.is_none() {
                // Read in basic data required to read a message
                let mut size_raw: [u8; 4] = [0; 4];
                let mut magic_raw: [u8; 4] = [0; 4];
                socket.read(&mut size_raw)?;
                socket.read(&mut magic_raw)?;

                // Check if the magic is correct, abort if not
                if String::from_utf8(magic_raw.to_vec())? != "VT01" {
                    println!("Wrong magic: {:#?}", magic_raw);
                    break; // Wrong magic, abort
                } else {
                    println!("Correct magic");
                    message_length = Some(i32::from_le_bytes(size_raw));
                }
            } else {
                // Fetch the data
                let data: Vec<u8> = socket
                    .bytes()
                    .take(message_length.unwrap() as usize)
                    .map(|x| x.unwrap()) // I hate this, but this will have to do
                    .collect();

                let kind = u32::from_le_bytes(data[0..4].try_into()?) & !0x80000000;

                match kind {
                    1303 => {
                        // Channel encrypt request
                        let target_job_id = u64::from_le_bytes(data[4..12].try_into()?);
                        let source_job_id = u64::from_le_bytes(data[12..20].try_into()?);
                        println!("{}, {}", target_job_id, source_job_id);

                        let protocol = u32::from_le_bytes(data[20..24].try_into()?);
                        let universe = u32::from_le_bytes(data[24..28].try_into()?);
                        let nonce = &data[28..44]; // Used to build the crypto key

                        println!("Proto: {}", protocol);
                        println!("Universe: {}", universe);

                        let session_key =
                            crate::steam_crypto::SessionKey::generate(nonce.try_into()?)?;

                        let mut response: Vec<u8> = vec![];
                        response.extend(&protocol.to_le_bytes());
                        response.extend(&(session_key.encrypted.len() as u32).to_le_bytes());
                        response.extend(&session_key.encrypted);
                        response.extend(
                            &(crc::crc32::checksum_ieee(&session_key.encrypted) as u32)
                                .to_le_bytes(),
                        );
                        response.extend(&(0 as u32).to_le_bytes());

                        const JOBID_NONE: u64 = 18446744073709551615;
                        // Send with emsg ChannelEncryptResponse
                        let mut response_header: Vec<u8> = vec![];
                        response_header.extend(&(1304 as u32).to_le_bytes());
                        response_header.extend(&JOBID_NONE.to_le_bytes());
                        response_header.extend(&JOBID_NONE.to_le_bytes());

                        socket.write_all(
                            &[
                                &(response.len() as u32 + response_header.len() as u32)
                                    .to_le_bytes() as &[u8],
                                "VT01".as_bytes(),
                                &response_header,
                                &response,
                            ]
                            .concat(),
                        )?;
                    }
                    _ => println!("Recieved {}", kind),
                }

                message_length = None;
            }
        }

        Ok(())
    }
}
