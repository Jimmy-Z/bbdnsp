
use log::*;

pub mod msg;
pub mod cvec;

pub use msg::*;


pub type DName = cvec::CVec<u8, 63>;
// #[cfg(debug_assertions)]
// assert_eq!(std::mem::size_of::<DName>(), 64);

impl DName {
	pub fn txt(txt: &[&str]) -> Self {
		let mut d = DName::new();
		for &line in txt {
			let mut len = line.len();
			if len > u8::MAX as usize {
				warn!("txt record truncated: \"{}\"({})", line, len);
				len = u8::MAX as usize;
			}
			d.push(len as u8);
			d.extend_from_slice(&line.as_bytes()[0..len]);
		}
		d
	}
}

// byte offset, bit offset, name, for easier enumeration/display only
// caution: in rfc1035 4.1.1 (and rfc6895 2), 0 actually denotes the highest bit
// ad and cd were introduced in rfc2535 6.7
pub const FLAGS: &[(u8, u8, &str)] = &[
	(2, 7, "qr"), // query or response
	// 4 bits gap here is opcode
	(2, 2, "aa"), // authoritative answer
	(2, 1, "tc"), // truncated
	(2, 0, "rd"), // recursive desired
	(3, 7, "ra"), // recursive available
	(3, 6, "z"),  // zero
	(3, 5, "ad"), // authentic data
	(3, 4, "cd"), // checking disabled
	              // 4 bits afterwards is rcode
];

#[derive(PartialEq, Eq, Debug)]
pub struct OpCode(pub u8);
impl OpCode {
	pub const QUERY: Self = Self(0);
}
impl std::fmt::Display for OpCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::QUERY => "Query",
			Self(1) => "IQUERY",
			Self(2) => "STATUS",
			Self(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct RCode(pub u8);
impl RCode {
	pub const NOERROR: Self = Self(0);
	pub const FORMERR: Self = Self(1);
	pub const SERVFAIL: Self = Self(2);
	pub const NXDOMAIN: Self = Self(3);
	pub const NOTIMP: Self = Self(4);
	pub const REFUSED: Self = Self(5);
}
impl std::fmt::Display for RCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::NOERROR => "NoError",
			&Self::FORMERR => "FormErr",
			&Self::SERVFAIL => "ServFail",
			&Self::NXDOMAIN => "NxDomain",
			&Self::NOTIMP => "NotImp",
			&Self::REFUSED => "Refused",
			Self(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct QClass(pub u16);
impl QClass {
	pub const IN: Self = Self(1);
	pub const CH: Self = Self(3);
}
impl std::fmt::Display for QClass {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::IN => "IN",
			&Self::CH => "CH",
			Self(255) => "any",
			Self(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct QType(pub u16);
impl QType {
	pub const A: Self = Self(1);
	pub const CNAME: Self = Self(5);
	pub const PTR: Self = Self(12);
	pub const TXT: Self = Self(16);
	pub const AAAA: Self = Self(28);
}
impl std::fmt::Display for QType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::A => "A",
			&Self::AAAA => "AAAA",
			&Self::CNAME => "CNAME",
			&Self::PTR => "PTR",
			&Self::TXT => "TXT",
			Self(2) => "NS",
			Self(64) => "SVCB",
			Self(65) => "HTTPS",
			Self(t) => return write!(f, "{}", t),
		};
		write!(f, "{}", s)
	}
}
impl TryFrom<&[u8]> for QType {
	type Error = ();
	fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
		match s {
			b"a" => Ok(Self::A),
			_ => Err(()),
		}
	}
}
