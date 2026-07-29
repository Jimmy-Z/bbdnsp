pub mod msg;

pub mod cvec;

pub const DNS_HEADER_LEN: usize = 12;

pub mod flags {
	// byte offset, bit offset, name, for easier enumeration/display only
	// caution: in rfc1035 4.1.1 (and rfc6895 2), 0 actually denotes the highest bit
	// ad and cd were introduced in rfc2535 6.7
	pub const LIST: &[(u8, u8, &str)] = &[
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
}

pub mod opcode {
	pub const QUERY: u8 = 0;
	const STR_TABLE: &[&str] = &["Query", "IQUERY", "STATUS"];
	pub fn to_str(c: u8) -> &'static str {
		super::code2str(STR_TABLE, QUERY as u16, c as u16)
	}
}

pub mod rcode {
	pub const NOERROR: u8 = 0;
	pub const FORMERR: u8 = 1;
	pub const SERVFAIL: u8 = 2;
	pub const NXDOMAIN: u8 = 3;
	pub const NOTIMP: u8 = 4;
	pub const REFUSED: u8 = 5;
	const STR_TABLE: &[&str] = &[
		"NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused",
	];
	pub fn to_str(c: u8) -> &'static str {
		super::code2str(STR_TABLE, NOERROR as u16, c as u16)
	}
}

pub mod qclass {
	pub const IN: u16 = 1;
	pub const CH: u16 = 3;
	const STR_TABLE: &[&str] = &["IN", "CS", "CH", "HS"];
	pub fn to_str(c: u16) -> &'static str {
		super::code2str(STR_TABLE, IN, c)
	}
}

pub mod qtype {
	pub const A: u16 = 1;
	pub const CNAME: u16 = 5;
	pub const AAAA: u16 = 28; // rfc3596
	pub fn to_str(c: u16) -> &'static str {
		match c {
			A => "A",
			AAAA => "AAAA",
			_ => "",
		}
	}
}

fn code2str(table: &'static [&'static str], base: u16, c: u16) -> &'static str {
	let c = (c - base) as usize;
	if c < table.len() { table[c] } else { "" }
}
