use std::net::{Ipv4Addr, UdpSocket};

use dns::{msg::RData, *};

fn main() -> std::io::Result<()> {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

	let d = UdpSocket::bind("127.0.0.1:1053")?;

	let mut buf = [0; 0x600];
	loop {
		let (len, addr) = d.recv_from(&mut buf)?;
		eprintln!("{len} bytes from {addr}");
		let msg = Msg::try_from((&mut buf[..], len));
		if msg.is_err() {
			continue;
		}
		let mut msg = msg.unwrap();
		println!("{msg}");
		let len = match msg.get_query() {
			Ok((q, offset)) => {
				eprintln!("{}", q);
				msg.answer(offset, &[Answer{
					qtype: QType::A,
					qclass: QClass::IN,
					ttl: 2501,
					rdata: RData::A(Ipv4Addr::new(127, 25, 0, 1))
				}]) as usize
			}
			Err(ParseError::UnkOpCode(_)) => {
				msg.deny(RCode::NOTIMP);
				len
			}
			Err(ParseError::FormErr) => continue,
			_ => unreachable!()
		};
		 if len > 0 {
		 	eprintln!("{len} bytes to {addr}");
		 	let msg = Msg::try_from((&mut buf[..], len)).unwrap();
		 	eprintln!("{msg}");
		 	d.send_to(&buf[..len], addr)?;
		 }
	}
}
