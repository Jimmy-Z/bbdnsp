use std::net::{Ipv4Addr, UdpSocket};

use log::*;

use dns::{msg::RData, *};

fn main() -> std::io::Result<()> {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

	let d = UdpSocket::bind("127.0.0.1:1053")?;

	let mut buf = [0; 0x600];
	loop {
		let (len, addr) = d.recv_from(&mut buf)?;
		info!("{len} bytes from {addr}");
		let msg = Msg::try_from((&mut buf[..], len));
		if msg.is_err() {
			continue;
		}
		let mut msg = msg.unwrap();
		eprintln!("{msg}");
		match msg.get_query() {
			Ok(q) => {
				info!("{}", q);
				handle(&mut msg, &q)
			}
			Err(ParseError::UnkOpCode(_)) => {
				msg.deny(RCode::NOTIMP);
			}
			Err(ParseError::FormErr) => continue,
			_ => unreachable!(),
		};
		let len = msg.len();
		if msg.len() > 0 {
			info!("{len} bytes to {addr}");
			// let msg = Msg::try_from((&mut buf[..], len)).unwrap();
			eprintln!("{msg}");
			d.send_to(&buf[..len], addr)?;
		}
	}
}

fn handle(msg: &mut Msg, q: &Query) {
	if q.qclass != QClass::IN {
		msg.deny(RCode::NOTIMP);
		return;
	}
	match q.qtype {
		QType::A => msg.answer(&[Answer {
			qtype: QType::A,
			qclass: QClass::IN,
			ttl: 2501,
			rdata: RData::A(Ipv4Addr::new(127, 25, 0, 1)),
		}]),
		QType::TXT => msg.answer(&[Answer {
			qtype: QType::TXT,
			qclass: QClass::IN,
			ttl: 2501,
			rdata: RData::Bytes(DName::txt(&["you're (not) welcome,", "\t(not) really."])),
		}]),
		_ => msg.deny(RCode::NOTIMP),
	}
}
