use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

use log::*;

use dns::*;

fn main() -> std::io::Result<()> {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

	let d = UdpSocket::bind("127.0.0.1:1053")?;

	// unlike tokio sockets, std sockets doesn't support BufMut
	// wants &mut [u8], which must be initialized
	let mut buf = vec![0; MSG_LEN_MAX];
	loop {
		let (len, addr) = d.recv_from(&mut buf)?;
		buf.resize(len, 0);
		info!("{len} bytes from {addr}");
		let msg = Msg::try_from(&mut buf);
		if msg.is_err() {
			buf.resize(MSG_LEN_MAX, 0);
			continue;
		}
		let mut msg = msg.unwrap();
		eprintln!("{msg}");
		match msg.get_query() {
			Ok(q) => {
				info!("{}", q);
				handle(&mut msg, &q)
			}
			Err(MsgError::UnkOpCode(_)) => {
				msg.deny(RCode::NOTIMP);
			}
			Err(MsgError::FormErr) => continue,
			_ => unreachable!(),
		};
		info!("{} bytes to {addr}", msg.len());
		// let msg = Msg::try_from((&mut buf[..], len)).unwrap();
		eprintln!("{msg}");
		d.send_to(&buf[..], addr)?;
		buf.resize(MSG_LEN_MAX, 0);
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
		QType::AAAA => msg.answer(&[Answer {
			qtype: QType::AAAA,
			qclass: QClass::IN,
			ttl: 2501,
			rdata: RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x2501)),
		}]),
		QType::TXT => msg.answer(&[Answer {
			qtype: QType::TXT,
			qclass: QClass::IN,
			ttl: 2501,
			rdata: RData::Raw(CVec63::txt(&["you're (not) welcome", "(not) really."])),
		}]),
		_ => msg.deny(RCode::NOTIMP),
	}
}
