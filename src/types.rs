use std::{fmt, net::IpAddr, num::NonZeroU32};

use serde::Serialize;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
	Udp,
	Tcp,
}

impl fmt::Display for Protocol {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Tcp => write!(f, "tcp")?,
			Self::Udp => write!(f, "udp")?,
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
	Ipv4,
	Ipv6,
}

impl fmt::Display for AddressFamily {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Ipv4 => write!(f, "ipv4")?,
			Self::Ipv6 => write!(f, "ipv6")?,
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Process {
	pub pid: u32,
	pub name: Option<String>,
	pub fd: u64,
}

impl fmt::Display for Process {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match &self.name {
			Some(name) => write!(f, "({name:?},pid={},fd={})", self.pid, self.fd),
			None => write!(f, "{}", self.pid),
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Interface {
	pub id: NonZeroU32,
	pub name: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AddrPort {
	pub address: IpAddr,
	pub port: u16,
	pub interface: Option<Interface>,
}

impl fmt::Display for AddrPort {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.address.is_ipv6() {
			write!(f, "[")?;
		}
		write!(f, "{}", self.address)?;
		if let Some(interface) = &self.interface {
			write!(f, "%")?;
			if let Some(name) = &interface.name {
				write!(f, "{name}")?;
			} else {
				write!(f, "{}", interface.id)?;
			}
		}
		if self.address.is_ipv6() {
			write!(f, "]")?;
		}
		write!(f, ":")?;
		if self.port == 0 {
			write!(f, "*")?;
		} else {
			write!(f, "{}", self.port)?;
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct User {
	pub uid: u32,
	pub username: Option<String>,
}

impl fmt::Display for User {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if let Some(username) = &self.username {
			write!(f, "{username}")?;
		} else {
			write!(f, "{}", self.uid)?;
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Record {
	pub protocol: Protocol,
	pub address_family: AddressFamily,
	pub from: AddrPort,
	pub to: AddrPort,
	pub state: u8,
	pub inode: u32,
	pub user: User,
	pub processes: Vec<Process>,
	pub v6only: Option<bool>,
}

impl Ord for Record {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.protocol
			.cmp(&other.protocol)
			.then_with(|| self.from.port.cmp(&other.from.port))
			.then_with(|| {
				self.from
					.address
					.is_ipv4()
					.cmp(&other.from.address.is_ipv4())
			})
			.then_with(|| self.from.address.cmp(&other.from.address))
			.then_with(|| self.to.address.cmp(&other.to.address))
	}
}

impl PartialOrd for Record {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}
