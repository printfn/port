use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
	/// Enable JSON output
	#[arg(short, long)]
	pub json: bool,

	/// Enable verbose output
	#[arg(short, long)]
	pub verbose: bool,

	/// Show TCP sockets only
	#[arg(short, long)]
	pub tcp: bool,

	/// Show UDP sockets only
	#[arg(short, long)]
	pub udp: bool,
}
