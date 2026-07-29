use std::{
	fmt::Display,
	net::{Ipv4Addr, Ipv6Addr},
};

use log::*;

use super::*;

pub const MSG_HEADER_LEN: usize = 12;
// technically shortest query:
// 1 byte length(0), qtype, qclass
pub const MSG_LEN_MIN: usize = MSG_HEADER_LEN + 1 + 2 + 2;

pub const MSG_LEN_MAX: usize = 1232;

#[derive(Debug)]
pub enum ParseError {
	UnkOpCode(OpCode),
	Truncated,
	FormErr,
}

type Result = std::result::Result<Query, ParseError>;

const FORMERR: Result = Err(ParseError::FormErr);

pub struct Query {
	pub name: DName,
	pub qtype: QType,
	pub qclass: QClass,
}

impl Display for Query {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}. {} {}", self.name, self.qtype, self.qclass)
	}
}

pub struct Answer {
	// pub name: DName,
	pub qtype: QType,
	pub qclass: QClass,
	pub ttl: u32,
	pub rdata: RData,
}

pub enum RData {
	A(Ipv4Addr),
	AAAA(Ipv6Addr),
	Bytes(DName),
}

impl RData {
	fn len(&self) -> u16 {
		match self {
			Self::A(_) => 4,
			Self::AAAA(_) => 16,
			Self::Bytes(b) => b.len() as u16,
		}
	}
}

pub struct Msg<'a> {
	msg: &'a mut [u8],
	len: u16,
}

impl<'a> Msg<'a> {
	pub fn get_query(&mut self) -> Result {
		// check headers
		let opcode = self.opcode();
		if opcode != OpCode::QUERY {
			return Err(ParseError::UnkOpCode(opcode));
		}
		if self.qd_count() < 1 {
			return FORMERR;
		}

		let mut offset = MSG_HEADER_LEN;
		// fqdn max len 255
		let mut name = DName::new();
		// name
		let mut label_len = self.msg[offset] as usize;
		if label_len > 0 {
			loop {
				if offset + 1 + label_len + 1 > self.len as usize {
					return FORMERR;
				}
				name.extend_from_slice(&self.msg[offset + 1..offset + 1 + label_len]);
				offset += 1 + label_len;
				// peek next label len to prevent adding a trailing dot
				label_len = self.msg[offset] as usize;
				if label_len == 0 {
					offset += 1;
					break;
				}
				name.push(b'.');
			}
		} else {
			offset += 1;
		}

		if !name.as_ref().is_ascii() {
			return FORMERR;
		};
		// QTYPE QCLASS
		if offset + 4 > self.len as usize {
			return FORMERR;
		}
		let q = Query {
			name,
			qtype: QType(u16be(&self.msg[offset..offset + 2])),
			qclass: QClass(u16be(&self.msg[offset + 2..offset + 4])),
		};
		// debug!("{}", q);
		offset += 4;
		self.len = offset as u16;
		Ok(q)
	}

	pub fn deny(&mut self, rcode: RCode) {
		self.set_response();
		self.set_rcode(rcode);
	}

	pub fn answer(&mut self, a: &[Answer]) {
		// start writing response
		self.set_response_header(RCode::NOERROR, 1, a.len() as u16, 0, 0);
		for a in a {
			self.inner_write_answer(a);
		}
	}

	pub fn inner_write_answer(&mut self, a: &Answer) {
		// to do: check available buffer
		let offset = self.len as usize;
		// rfc1034 4.1.4 message compression
		// qname is conveniently always just after the header
		const QNAME_OFFSET: u16 = 0b1100_0000_0000_0000 | MSG_HEADER_LEN as u16;
		self.msg[offset..offset + 2].copy_from_slice(&QNAME_OFFSET.to_be_bytes());
		self.msg[offset + 2..offset + 4].copy_from_slice(&a.qtype.0.to_be_bytes());
		self.msg[offset + 4..offset + 6].copy_from_slice(&a.qclass.0.to_be_bytes());
		self.msg[offset + 6..offset + 10].copy_from_slice(&a.ttl.to_be_bytes());

		let len = a.rdata.len();
		self.msg[offset + 10..offset + 12].copy_from_slice(&a.rdata.len().to_be_bytes());
		match &a.rdata {
			RData::A(a) => {
				self.msg[offset + 12..offset + 12 + len as usize].copy_from_slice(&a.octets());
			}
			RData::AAAA(a) => {
				self.msg[offset + 12..offset + 12 + len as usize].copy_from_slice(&a.octets());
			}
			RData::Bytes(b) => {
				self.msg[offset + 12..offset + 12 + len as usize].copy_from_slice(b.as_ref());
			}
		}
		self.len += 12 + len
	}

	fn set_response_header(&mut self, rcode: RCode, qd: u16, an: u16, ns: u16, ar: u16) {
		self.set_response_ra();
		self.set_rcode(rcode);
		self.msg[4..6].copy_from_slice(&qd.to_be_bytes());
		self.msg[6..8].copy_from_slice(&an.to_be_bytes());
		self.msg[8..10].copy_from_slice(&ns.to_be_bytes());
		self.msg[10..12].copy_from_slice(&ar.to_be_bytes());
	}

	fn set_response_ra(&mut self) {
		self.set_response();
		if self.rd() {
			self.set_ra();
		}
	}

	fn id(&self) -> u16 {
		u16be(&self.msg[0..2])
	}
	fn qd_count(&self) -> u16 {
		u16be(&self.msg[4..6])
	}
	fn an_count(&self) -> u16 {
		u16be(&self.msg[6..8])
	}
	fn ns_count(&self) -> u16 {
		u16be(&self.msg[8..10])
	}
	fn ar_count(&self) -> u16 {
		u16be(&self.msg[10..12])
	}

	fn get_flag(&self, o_byte: u8, o_bit: u8) -> bool {
		get_bit(self.msg[o_byte as usize], o_bit)
	}

	fn tc(&self) -> bool {
		self.get_flag(2, 1)
	}
	fn rd(&self) -> bool {
		self.get_flag(2, 0)
	}
	fn z(&self) -> bool {
		self.get_flag(3, 6)
	}

	fn opcode(&self) -> OpCode {
		OpCode(get_bits(self.msg[2], 3, 4))
	}
	fn rcode(&self) -> RCode {
		RCode(get_bits(self.msg[3], 0, 4))
	}

	fn set_response(&mut self) {
		set_bit(&mut self.msg[2], 7)
	}
	fn set_ra(&mut self) {
		set_bit(&mut self.msg[3], 7)
	}
	fn set_rcode(&mut self, c: RCode) {
		set_bits(&mut self.msg[3], 0, 4, c.0);
	}

	#[allow(clippy::len_without_is_empty)]
	pub fn len(&self) -> usize {
		self.len as usize
	}
}

impl<'a> TryFrom<(&'a mut [u8], usize)> for Msg<'a> {
	type Error = ParseError;
	fn try_from(bytes: (&'a mut [u8], usize)) -> std::result::Result<Self, Self::Error> {
		let (bytes, len) = bytes;
		if len < MSG_LEN_MIN {
			debug!("too short to be a dns message: {len}");
			return Err(ParseError::FormErr);
		}
		// eprintln!("{:08b} {:08b}", msg[2], msg[3]);
		let msg = Msg {
			msg: bytes,
			len: len as u16,
		};
		if msg.tc() {
			debug!("header: truncated");
			return Err(ParseError::Truncated);
		}
		if msg.z() {
			debug!("header: reserved bit is not zero");
		}
		Ok(msg)
	}
}

// just the header, mimics drill/dig output
impl<'a> Display for Msg<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			";; ->>HEADER<<- opcode: {}, rcode: {}, id: {}\n;; flags:",
			self.opcode(),
			self.rcode(),
			self.id()
		)?;
		for &(o0, o1, name) in FLAGS {
			if self.get_flag(o0, o1) {
				write!(f, " {name}")?;
			}
		}
		writeln!(
			f,
			"; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
			self.qd_count(),
			self.an_count(),
			self.ns_count(),
			self.ar_count()
		)
	}
}

fn u16be(bytes: &[u8]) -> u16 {
	u16::from_be_bytes(bytes.try_into().unwrap())
}

// I really liked bit fields in C
fn get_bit(b: u8, o: u8) -> bool {
	(b >> o) & 1 == 1
}
fn get_bits(b: u8, o: u8, l: u8) -> u8 {
	(b >> o) & ((1 << l) - 1)
}
fn set_bit(b: &mut u8, o: u8) {
	*b |= 1 << o;
}
fn set_bits(b: &mut u8, o: u8, l: u8, v: u8) {
	*b = (*b & !(((1 << l) - 1) << o)) | (v << o);
}

#[cfg(test)]
mod tests {}
