// https://www.man7.org/linux/man-pages/man7/sock_diag.7.html

use std::{
	collections::{HashMap, HashSet},
	fs,
	io::{Read, Write},
	net::{Ipv4Addr, Ipv6Addr},
	num::NonZeroU32,
};

use neli::{
	FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
	consts::{nl::NlmF, rtnl::RtaType, socket::NlFamily},
	err::DeError,
	neli_enum,
	nl::{NlPayload, Nlmsghdr},
	router::asynchronous::NlRouter,
	types::{Buffer, RtBuffer},
	utils::Groups,
};

use crate::{
	args::Args,
	types::{AddrPort, AddressFamily, Interface, Process, Protocol, Record, User},
};

const SOCK_DIAG_BY_FAMILY: u8 = 20;
const TCP_LISTEN: u8 = 10; // https://github.com/torvalds/linux/blob/ca91b9500108d4cf083a635c2e11c884d5dd20ea/include/net/tcp_states.h#L22
const TCP_CLOSE: u8 = 7;
// const INET_DIAG_TCLASS: u8 = 6; // https://github.com/torvalds/linux/blob/b6ea1680d0ac0e45157a819c41b46565f4616186/include/uapi/linux/inet_diag.h#L141

// https://github.com/torvalds/linux/blob/b6ea1680d0ac0e45157a819c41b46565f4616186/include/uapi/linux/inet_diag.h#L134
#[neli_enum(serialized_type = "u16")]
pub enum InetDiag {
	InetDiagNone = 0,
	InetDiagMeminfo = 1,
	InetDiagInfo = 2,
	InetDiagVegasinfo = 3,
	InetDiagCong = 4,
	InetDiagTos = 5,
	InetDiagTclass = 6,
	InetDiagSkmeminfo = 7,
	InetDiagShutdown = 8,

	/*
	 * Next extensions cannot be requested in struct inet_diag_req_v2:
	 * its field idiag_ext has only 8 bits.
	 */
	InetDiagDctcpinfo = 9, /* request as INET_DIAG_VEGASINFO */
	InetDiagProtocol = 10, /* response attribute only */
	InetDiagSkv6only = 11,
	InetDiagLocals = 12,
	InetDiagPeers = 13,
	InetDiagPad = 14,
	InetDiagMark = 15,    /* only with CAP_NET_ADMIN */
	InetDiagBbrinfo = 16, /* request as INET_DIAG_VEGASINFO */
	InetDiagClassId = 17, /* request as INET_DIAG_TCLASS */
	InetDiagMd5sig = 18,
	InetDiagUlpInfo = 19,
	InetDiagSkBpfStorages = 20,
	InetDiagCgroupId = 21,
	InetDiagSockopt = 22,
}

impl RtaType for InetDiag {}

#[derive(Debug, Size, Clone, Copy)]
struct Be16(u16);

impl TypeSize for Be16 {
	fn type_size() -> usize {
		size_of::<Self>()
	}
}

impl ToBytes for Be16 {
	fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
		buffer.write_all(&self.0.to_be_bytes())?;
		Ok(())
	}
}

impl FromBytes for Be16 {
	fn from_bytes(
		buffer: &mut std::io::Cursor<impl AsRef<[u8]>>,
	) -> Result<Self, neli::err::DeError> {
		let mut b = [0; 2];
		buffer.read_exact(&mut b)?;
		Ok(Self(u16::from_be_bytes(b)))
	}
}

#[derive(Debug, Clone, Default, Copy)]
struct Beu32_4([u32; 4]);

impl Size for Beu32_4 {
	fn unpadded_size(&self) -> usize {
		size_of::<Self>()
	}
}

impl TypeSize for Beu32_4 {
	fn type_size() -> usize {
		size_of::<Self>()
	}
}

impl ToBytes for Beu32_4 {
	fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
		buffer.write_all(&self.0[0].to_be_bytes())?;
		buffer.write_all(&self.0[1].to_be_bytes())?;
		buffer.write_all(&self.0[2].to_be_bytes())?;
		buffer.write_all(&self.0[3].to_be_bytes())?;
		Ok(())
	}
}

impl FromBytes for Beu32_4 {
	fn from_bytes(
		buffer: &mut std::io::Cursor<impl AsRef<[u8]>>,
	) -> Result<Self, neli::err::DeError> {
		let mut result = Self([0; 4]);
		let mut b = [0; 4];
		for i in 0..4 {
			buffer.read_exact(&mut b)?;
			result.0[i] = u32::from_be_bytes(b);
		}
		Ok(result)
	}
}

impl Beu32_4 {
	fn as_ipv4(&self) -> Ipv4Addr {
		Ipv4Addr::from_bits(self.0[0])
	}

	fn as_ipv6(&self) -> Ipv6Addr {
		let mut bytes = [0; 16];
		for i in 0..16 {
			bytes[i] = self.0[i / 4].to_be_bytes()[i % 4];
		}
		Ipv6Addr::from_bits(u128::from_be_bytes(bytes))
	}
}

#[derive(Clone, Debug, Size, ToBytes, FromBytesWithInput, FromBytes)]
struct InetDiagSockId {
	idiag_sport: Be16,
	idiag_dport: Be16,
	idiag_src: Beu32_4,
	idiag_dst: Beu32_4,
	idiag_if: u32,
	idiag_cookie: u64,
}

impl TypeSize for InetDiagSockId {
	fn type_size() -> usize {
		size_of::<Self>()
	}
}

#[derive(Clone, Debug, Size, ToBytes, FromBytesWithInput)]
struct InetDiagRequestV2 {
	sdiag_family: u8,
	sdiag_protocol: u8,
	idiag_ext: u8,
	pad: u8,
	idiag_states: u32,
	id: InetDiagSockId,
}

#[derive(Clone, Debug, Size, ToBytes, FromBytesWithInput, Header)]
struct InetDiagMsg {
	idiag_family: u8,
	idiag_state: u8,
	idiag_timer: u8,
	idiag_retrans: u8,
	id: InetDiagSockId,
	idiag_expires: u32,
	idiag_rqueue: u32,
	idiag_wqueue: u32,
	idiag_uid: u32,
	idiag_inode: u32,
	#[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
	rtattrs: RtBuffer<InetDiag, Buffer>,
}

fn fmt_addr(family: AddressFamily, addr: Beu32_4, port: Be16, interface_id: u32) -> AddrPort {
	let mut interface = None;
	if let Some(interface_id) = NonZeroU32::new(interface_id) {
		let mut i = Interface {
			id: interface_id,
			name: None,
		};
		let name = nix::net::if_::if_indextoname(interface_id.into());
		if let Ok(name) = name {
			if let Ok(name) = name.into_string() {
				i.name = Some(name);
			}
		}
		interface = Some(i);
	}
	AddrPort {
		address: match family {
			AddressFamily::Ipv4 => addr.as_ipv4().into(),
			AddressFamily::Ipv6 => addr.as_ipv6().into(),
		},
		port: port.0,
		interface,
	}
}

fn get_process(pid: u32, fd: u64) -> Process {
	let mut result = Process {
		name: None,
		pid,
		fd,
	};
	if let Ok(mut s) = fs::read_to_string(format!("/proc/{pid}/comm")) {
		if s.ends_with('\n') {
			s.pop();
		}
		if !s.is_empty() {
			result.name = Some(s);
		}
	}
	result
}

async fn neli(
	args: &Args,
	result: &mut Vec<Record>,
	socket: &NlRouter,
	address_family: AddressFamily,
	proto: Protocol,
) -> eyre::Result<()> {
	let payload = NlPayload::Payload(InetDiagRequestV2 {
		sdiag_family: match address_family {
			AddressFamily::Ipv4 => libc::AF_INET,
			AddressFamily::Ipv6 => libc::AF_INET6,
		} as u8,
		sdiag_protocol: match proto {
			Protocol::Tcp => libc::IPPROTO_TCP,
			Protocol::Udp => libc::IPPROTO_UDP,
		} as u8,
		idiag_ext: match proto {
			Protocol::Tcp => {
				1 << (u16::from(InetDiag::InetDiagTclass) - 1)
					| 1 << (u16::from(InetDiag::InetDiagInfo) - 1)
			}
			Protocol::Udp => 0,
		},
		pad: 0,
		idiag_states: match proto {
			Protocol::Tcp => 1 << (TCP_LISTEN as u32),
			Protocol::Udp => 1 << (TCP_LISTEN as u32) | 1 << (TCP_CLOSE as u32),
		},
		id: InetDiagSockId {
			idiag_sport: Be16(0),
			idiag_dport: Be16(0),
			idiag_src: Beu32_4::default(),
			idiag_dst: Beu32_4::default(),
			idiag_if: 0,
			idiag_cookie: 0,
		},
	});
	if args.verbose {
		eprintln!("sending payload: {:?}", payload);
	}
	let mut recv = socket
		.send::<u16, InetDiagRequestV2, u16, InetDiagMsg>(
			SOCK_DIAG_BY_FAMILY as u16,
			NlmF::DUMP,
			payload,
		)
		.await?;

	while let Some(msg) = recv.next().await {
		if args.verbose {
			eprintln!("received payload: {msg:?}");
		}
		let mut msg: Nlmsghdr<u16, InetDiagMsg> = msg?;
		if let Some(err) = msg.get_err() {
			eyre::bail!("Error: {err}");
		}
		let Some(payload) = msg.get_payload() else {
			continue;
		};
		if *msg.nl_type() != u16::from(SOCK_DIAG_BY_FAMILY) {
			eyre::bail!(
				"Error: unexpected netlink message type {} (expected {SOCK_DIAG_BY_FAMILY})",
				msg.nl_type()
			);
		}
		let mut record = Record {
			protocol: proto,
			address_family,
			from: fmt_addr(
				address_family,
				payload.id.idiag_src,
				payload.id.idiag_sport,
				payload.id.idiag_if,
			),
			to: fmt_addr(
				address_family,
				payload.id.idiag_dst,
				payload.id.idiag_dport,
				0,
			),
			state: payload.idiag_state,
			user: User {
				uid: payload.idiag_uid,
				username: None,
			},
			inode: payload.idiag_inode,
			processes: vec![], //resolve_inode(payload.idiag_inode).unwrap_or_default(),
			v6only: None,
		};
		for attr in payload.rtattrs.get_attr_handle().get_attrs() {
			let payload = attr.rta_payload();
			if args.verbose {
				let mut bytes = std::io::Cursor::new(vec![0; payload.len()]);
				payload.to_bytes(&mut bytes)?;
				eprintln!(" attr {:?}: {:?}", attr.rta_type(), bytes.get_ref());
			}
			match attr.rta_type() {
				InetDiag::InetDiagSkv6only => {
					record.v6only = Some(payload.as_ref()[0] != 0);
				}
				_ => (),
			}
		}
		result.push(record);
	}

	Ok(())
}

pub fn fill_usernames(result: &mut Vec<Record>) {
	let mut usernames = HashMap::new();
	for r in result {
		let entry = usernames.entry(r.user.uid).or_insert_with_key(|&uid| {
			nix::unistd::User::from_uid(uid.into())
				.unwrap_or(None)
				.map(|u| u.name)
		});
		if let Some(user) = entry {
			r.user.username = Some(user.clone());
		}
	}
}

pub fn fill_processes(result: &mut Vec<Record>) -> eyre::Result<()> {
	let inodes: HashSet<_> = result.iter().map(|r| r.inode).collect();
	let mut inode_data: HashMap<u32, Vec<Process>> = HashMap::new();
	for entry in fs::read_dir("/proc")? {
		let Ok(entry) = entry else {
			continue;
		};
		let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
			continue;
		};
		let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
			continue;
		};
		for fd_file in fds {
			let Ok(fd_file) = fd_file else {
				continue;
			};
			let fd = fd_file.file_name();
			let Some(fd) = fd.to_str() else {
				continue;
			};
			let Ok(fd) = fd.parse::<u64>() else {
				continue;
			};
			let Ok(target) = fs::read_link(fd_file.path()) else {
				continue;
			};
			let Some(target) = target.to_str() else {
				continue;
			};
			if !target.starts_with("socket:[") || !target.ends_with(']') {
				continue;
			}
			let Ok(inode) = target[8..target.len() - 1].parse::<u32>() else {
				continue;
			};
			if inodes.contains(&inode) {
				let process = get_process(pid, fd);
				inode_data.entry(inode).or_default().push(process);
			}
		}
	}
	for r in result {
		if let Some(processes) = inode_data.get(&r.inode) {
			r.processes = processes.clone();
		}
	}
	Ok(())
}

pub async fn load_data(args: &Args) -> eyre::Result<Vec<Record>> {
	let (socket, _) = NlRouter::connect(NlFamily::SockOrInetDiag, None, Groups::empty()).await?;
	let mut r = vec![];
	if args.udp || !args.tcp {
		neli(args, &mut r, &socket, AddressFamily::Ipv4, Protocol::Udp).await?;
		neli(args, &mut r, &socket, AddressFamily::Ipv6, Protocol::Udp).await?;
	}
	if args.tcp || !args.udp {
		neli(args, &mut r, &socket, AddressFamily::Ipv4, Protocol::Tcp).await?;
		neli(args, &mut r, &socket, AddressFamily::Ipv6, Protocol::Tcp).await?;
	}
	fill_usernames(&mut r);
	fill_processes(&mut r)?;
	Ok(r)
}
