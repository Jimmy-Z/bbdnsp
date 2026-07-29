pub mod msg;

pub mod cvec;

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

#[derive(PartialEq, Eq)]
pub struct OpCode(pub u8);
impl OpCode {
	const QUERY: OpCode = OpCode(0);
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

pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;
pub struct RCode(pub u8);
impl std::fmt::Display for RCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self.0 {
			NOERROR => "NoError",
			FORMERR => "FormErr",
			SERVFAIL => "ServFail",
			NXDOMAIN => "NxDomain",
			NOTIMP => "NotImp",
			REFUSED => "Refused",
			_ => return write!(f, "{}", self.0),
		};
		write!(f, "{}", s)
	}
}

pub const IN: u16 = 1;
pub const CH: u16 = 3;
pub struct QClass(pub u16);
impl std::fmt::Display for QClass {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.0 {
			IN => write!(f, "{}", "IN"),
			CH => write!(f, "{}", "CH"),
			255 => write!(f, "{}", "any"),
			_ => write!(f, "{}", self.0),
		}
	}
}

pub const A: u16 = 1;
pub const CNAME: u16 = 5;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28; // rfc3596
pub struct QType(pub u16);
impl std::fmt::Display for QType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.0 {
			A => write!(f, "{}", "A"),
			CNAME => write!(f, "{}", "CNAME"),
			TXT => write!(f, "{}", "TXT"),
			AAAA => write!(f, "{}", "AAAA"),
			_ => write!(f, "{}", self.0),
		}
	}
}
