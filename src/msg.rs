use std::{
	fmt::Display,
	net::{Ipv4Addr, Ipv6Addr},
};

use log::*;

use super::*;

pub const MSG_HEADER_LEN: usize = 12;
// technically shortest query:
// 1 byte name (root), qtype, qclass
pub const MSG_LEN_MIN: usize = MSG_HEADER_LEN + 1 + 2 + 2;

pub const MSG_LEN_MAX: usize = 1232;

// where is the source of it?
pub const FQDN_LEN_MAX: usize = 253;
pub const LABEL_LEN_MAX: usize = 63;

#[derive(Debug)]
pub enum MsgError {
	UnkOpCode(OpCode),
	Truncated,
	FormErr,
}

type Result<T> = std::result::Result<T, MsgError>;

pub struct Query {
	pub name: CVec63,
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
	Bytes(CVec63),
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
	buf: &'a mut [u8],
	len: u16,
	q_end: u16,
}

// rfc1034 4.1.4 message compression
const MC_SIG: u8 = 0b1100_0000;
const MC_SIG16: u16 = 0b1100_0000_0000_0000;
// qname is conveniently always just after the header
const MC_QNAME: u16 = MC_SIG16 | MSG_HEADER_LEN as u16;

impl<'a> Msg<'a> {
	pub fn get_query(&mut self) -> Result<Query> {
		// check headers
		let opcode = self.opcode();
		if opcode != OpCode::QUERY {
			return Err(MsgError::UnkOpCode(opcode));
		}
		if self.qd_count() != 1 {
			return Err(MsgError::FormErr);
		}

		let mut offset = MSG_HEADER_LEN;
		// fqdn max len 255
		let mut name = CVec63::new();
		// name
		let mut label_len = self.buf[offset] as usize;
		if label_len > 0 {
			loop {
				if offset + 1 + label_len + 1 > self.len as usize {
					return Err(MsgError::FormErr);
				}
				name.extend_from_slice(&self.buf[offset + 1..offset + 1 + label_len]);
				offset += 1 + label_len;
				// peek next label len to avoid the trailing dot
				label_len = self.buf[offset] as usize;
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
			return Err(MsgError::FormErr);
		};
		// QTYPE QCLASS
		if offset + 4 > self.len as usize {
			return Err(MsgError::FormErr);
		}
		let q = Query {
			name,
			qtype: QType(u16be(&self.buf[offset..offset + 2])),
			qclass: QClass(u16be(&self.buf[offset + 2..offset + 4])),
		};
		// debug!("{}", q);
		offset += 4;
		self.q_end = offset as u16;
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

	fn inner_write_answer(&mut self, a: &Answer) {
		// to do: check available buffer
		let offset = self.q_end as usize;
		// to do: currently all answers are direct
		self.buf[offset..offset + 2].copy_from_slice(&MC_QNAME.to_be_bytes());
		self.buf[offset + 2..offset + 4].copy_from_slice(&a.qtype.0.to_be_bytes());
		self.buf[offset + 4..offset + 6].copy_from_slice(&a.qclass.0.to_be_bytes());
		self.buf[offset + 6..offset + 10].copy_from_slice(&a.ttl.to_be_bytes());

		let len = a.rdata.len();
		self.buf[offset + 10..offset + 12].copy_from_slice(&a.rdata.len().to_be_bytes());
		match &a.rdata {
			RData::A(a) => {
				self.buf[offset + 12..offset + 12 + len as usize].copy_from_slice(&a.octets());
			}
			RData::AAAA(a) => {
				self.buf[offset + 12..offset + 12 + len as usize].copy_from_slice(&a.octets());
			}
			RData::Bytes(b) => {
				self.buf[offset + 12..offset + 12 + len as usize].copy_from_slice(b.as_ref());
			}
		}
		self.len += 12 + len
	}

	fn set_response_header(&mut self, rcode: RCode, qd: u16, an: u16, ns: u16, ar: u16) {
		self.set_response_ra();
		self.set_rcode(rcode);
		self.buf[4..6].copy_from_slice(&qd.to_be_bytes());
		self.buf[6..8].copy_from_slice(&an.to_be_bytes());
		self.buf[8..10].copy_from_slice(&ns.to_be_bytes());
		self.buf[10..12].copy_from_slice(&ar.to_be_bytes());
	}

	fn set_response_ra(&mut self) {
		self.set_response();
		if self.rd() {
			self.set_ra();
		}
	}

	fn id(&self) -> u16 {
		u16be(&self.buf[0..2])
	}
	fn qd_count(&self) -> u16 {
		u16be(&self.buf[4..6])
	}
	fn an_count(&self) -> u16 {
		u16be(&self.buf[6..8])
	}
	fn ns_count(&self) -> u16 {
		u16be(&self.buf[8..10])
	}
	fn ar_count(&self) -> u16 {
		u16be(&self.buf[10..12])
	}

	fn get_flag(&self, o_byte: u8, o_bit: u8) -> bool {
		get_bit(self.buf[o_byte as usize], o_bit)
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
		OpCode(get_bits(self.buf[2], 3, 4))
	}
	fn rcode(&self) -> RCode {
		RCode(get_bits(self.buf[3], 0, 4))
	}

	fn set_id(&mut self, id: u16) {
		self.buf[0..2].copy_from_slice(&id.to_be_bytes());
	}

	fn set_response(&mut self) {
		set_bit(&mut self.buf[2], 7)
	}
	fn set_rd(&mut self) {
		set_bit(&mut self.buf[2], 0)
	}
	fn set_ra(&mut self) {
		set_bit(&mut self.buf[3], 7)
	}
	fn set_opcode(&mut self, c: OpCode) {
		set_bits(&mut self.buf[2], 3, 4, c.0);
	}
	fn set_rcode(&mut self, c: RCode) {
		set_bits(&mut self.buf[3], 0, 4, c.0);
	}

	fn set_qd(&mut self, qd: u16) {
		self.buf[4..6].copy_from_slice(&qd.to_be_bytes());
	}

	#[allow(clippy::len_without_is_empty)]
	pub fn len(&self) -> usize {
		self.len as usize
	}
}

impl<'a> TryFrom<(&'a mut [u8], usize)> for Msg<'a> {
	type Error = MsgError;
	fn try_from(bytes: (&'a mut [u8], usize)) -> std::result::Result<Self, Self::Error> {
		let (bytes, len) = bytes;
		if len < MSG_LEN_MIN {
			debug!("too short to be a dns message: {len}");
			return Err(MsgError::FormErr);
		}
		// eprintln!("{:08b} {:08b}", msg[2], msg[3]);
		let msg = Msg {
			buf: bytes,
			len: len as u16,
			q_end: 0,
		};
		if msg.tc() {
			debug!("header: truncated");
			return Err(MsgError::Truncated);
		}
		if msg.z() {
			debug!("header: reserved bit is not zero");
		}
		Ok(msg)
	}
}

fn mk_query(buf: &mut [u8], id: u16, q: Query) -> Result<usize> {
	if q.name.len() > FQDN_LEN_MAX {
		return Err(MsgError::FormErr);
	}
	let mut msg = Msg {
		buf,
		len: 0,
		q_end: 0,
	};
	msg.set_id(id);
	msg.set_rd();
	msg.set_qd(1);
	let mut offset = MSG_HEADER_LEN;
	for l in q.name.as_ref().split(|&b| b == b'.') {
		if l.len() > LABEL_LEN_MAX {
			return Err(MsgError::FormErr);
		}
		msg.buf[offset] = l.len() as u8;
		msg.buf[offset + 1..offset + 1 + l.len()].copy_from_slice(l);
		offset += 1 + l.len();
	}
	msg.buf[offset] = 0;
	msg.buf[offset + 1..offset + 1 + 2].copy_from_slice(&q.qtype.0.to_be_bytes());
	msg.buf[offset + 3..offset + 3 + 2].copy_from_slice(&q.qclass.0.to_be_bytes());

	Ok(MSG_HEADER_LEN + 1 + q.name.len() + 1 + 2 + 2)
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
mod tests {
	use super::*;

	#[test]
	fn test_query() {
		let mut buf = [0u8; MSG_LEN_MAX];
		let l = mk_query(
			&mut buf,
			2501,
			Query {
				name: b"g.co".as_slice().into(),
				qtype: QType::A,
				qclass: QClass::IN,
			},
		).unwrap();
		let mut msg = Msg::try_from((&mut buf[..], l)).unwrap();
		eprintln!("{msg}");
		let q = msg.get_query().unwrap();
		assert_eq!(l, msg.len as usize);
		eprintln!("{q}");
	}
}
