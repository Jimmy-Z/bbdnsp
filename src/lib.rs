pub mod msg;

pub mod cvec;

pub use msg::*;

pub const DNS_HEADER_LEN: usize = 12;

pub type DName = cvec::CVec<u8, 63>;
// #[cfg(debug_assertions)]
// assert_eq!(std::mem::size_of::<DName>(), 64);

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
];
// 4 bits afterwards is rcode

#[derive(PartialEq, Eq, Debug)]
pub struct OpCode(pub u8);
impl OpCode {
	pub const QUERY: OpCode = OpCode(0);
}
impl std::fmt::Display for OpCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::QUERY => "Query",
			OpCode(1) => "IQUERY",
			OpCode(2) => "STATUS",
			OpCode(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct RCode(pub u8);
impl RCode {
	pub const NOERROR: RCode = RCode(0);
	pub const FORMERR: RCode = RCode(1);
	pub const SERVFAIL: RCode = RCode(2);
	pub const NXDOMAIN: RCode = RCode(3);
	pub const NOTIMP: RCode = RCode(4);
	pub const REFUSED: RCode = RCode(5);
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
			RCode(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct QClass(pub u16);
impl QClass {
	pub const IN: QClass = QClass(1);
	pub const CH: QClass = QClass(3);
}
impl std::fmt::Display for QClass {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::IN => "IN",
			&Self::CH => "CH",
			QClass(255) => "any",
			QClass(c) => return write!(f, "{}", c),
		};
		write!(f, "{}", s)
	}
}

#[derive(PartialEq, Eq)]
pub struct QType(pub u16);
impl QType {
	pub const A: QType = QType(1);
	pub const CNAME: QType = QType(5);
	pub const TXT: QType = QType(16);
	pub const AAAA: QType = QType(28);
}
impl std::fmt::Display for QType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			&Self::A => "A",
			&Self::CNAME => "CNAME",
			&Self::TXT => "TXT",
			&Self::AAAA => "AAAA",
			QType(t) => return write!(f, "{}", t),
		};
		write!(f, "{}", s)
	}
}
