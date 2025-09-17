// src/ldap/asn1.rs

use std::io::{Cursor, Read};

#[derive(Debug, Clone)]
pub enum Asn1 {
    Integer(i64),
    Enumerated(u32),
    OctetString(Vec<u8>),
    Sequence(Vec<Asn1>),
    Set(Vec<Asn1>),
    Boolean(bool),
    Null,
}

#[derive(Debug)]
pub enum Asn1Error {
    InvalidLength,
    UnexpectedEof,
    UnsupportedType(u8),
    Io(std::io::Error),
}

impl From<std::io::Error> for Asn1Error {
    fn from(e: std::io::Error) -> Self {
        Asn1Error::Io(e)
    }
}

pub struct Asn1Parser {
    cursor: Cursor<Vec<u8>>,
}

impl Asn1Parser {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    pub fn parse(&mut self) -> Result<Option<Asn1>, Asn1Error> {
        if self.cursor.position() as usize >= self.cursor.get_ref().len() {
            return Ok(None);
        }

        let tag = self.read_u8()?;
        let length = self.read_length()?;
        let mut content = vec![0u8; length];
        self.cursor.read_exact(&mut content)?;

        let value = match tag {
            0x02 => Asn1::Integer(decode_integer(&content)?),
            0x0A => Asn1::Enumerated(decode_enumerated(&content)),
            0x04 => Asn1::OctetString(content),
            0x30 => {
                let mut parser = Asn1Parser::new(content);
                let mut items = Vec::new();
                while let Some(item) = parser.parse()? {
                    items.push(item);
                }
                Asn1::Sequence(items)
            }
            0x31 => {
                let mut parser = Asn1Parser::new(content);
                let mut items = Vec::new();
                while let Some(item) = parser.parse()? {
                    items.push(item);
                }
                Asn1::Set(items)
            }
            0x01 => Asn1::Boolean(content[0] != 0),
            0x05 => Asn1::Null,
            _ => return Err(Asn1Error::UnsupportedType(tag)),
        };

        Ok(Some(value))
    }

    fn read_u8(&mut self) -> Result<u8, std::io::Error> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_length(&mut self) -> Result<usize, Asn1Error> {
        let len_byte = self.read_u8()?;
        if len_byte & 0x80 == 0 {
            Ok(len_byte as usize)
        } else {
            let num_bytes = (len_byte & 0x7F) as usize;
            if num_bytes == 0 {
                return Err(Asn1Error::InvalidLength);
            }
            let mut len = 0;
            for _ in 0..num_bytes {
                len = (len << 8) + (self.read_u8()? as usize);
            }
            Ok(len)
        }
    }
}

fn decode_integer(bytes: &[u8]) -> Result<i64, Asn1Error> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut val: i64 = 0;
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    // Если старший бит установлен, это отрицательное число
    if bytes[0] & 0x80 != 0 {
        val -= (1i64 << (bytes.len() * 8)) as i64;
    }
    Ok(val)
}

fn decode_enumerated(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, &b| (acc << 8) | (b as u32))
}