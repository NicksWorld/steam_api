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
                let mut data: CMReader = CMReader::new(
                    socket
                        .bytes()
                        .take(message_length.unwrap() as usize)
                        .map(|x| x.unwrap()) // I hate this, but this will have to do
                        .collect(),
                );

                let kind = data.uint32()? & !0x80000000;

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

                        let session_key =
                            crate::steam_crypto::SessionKey::generate(nonce.try_into()?)?;

                        let response_body =
                            CMWriter::with_size(4 + 4 + session_key.encrypted.len() + 4 + 4)
                                .uint32(protocol)
                                .uint32(session_key.encrypted.len() as u32)
                                .bytes(&session_key.encrypted)
                                .uint32(crc::crc32::checksum_ieee(&session_key.encrypted) as u32)
                                .uint32(0)
                                .get_inner();

                        const JOBID_NONE: u64 = 18446744073709551615;

                        let response_header = CMWriter::with_size(4 + 8 + 8)
                            .uint32(1304)
                            .uint64(JOBID_NONE)
                            .uint64(JOBID_NONE)
                            .get_inner();

                        // Send the message
                        CMSocket::send_message(socket, &response_header, &response_body)?;
                    }
                    _ => println!("Recieved {}", kind),
                }

                message_length = None;
            }
        }

        Ok(())
    }
}
