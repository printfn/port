use std::io::stdout;

use args::Args;
use clap::Parser;
use serde::Serialize;
use ui::{Alignment, Column, Table};

mod args;
mod linux;
mod types;
mod ui;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	let args = Args::parse();
	let mut entries = linux::load_data(&args).await?;
	entries.sort();
	if args.json {
		let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
		let mut serializer = serde_json::ser::Serializer::with_formatter(stdout(), formatter);
		entries.serialize(&mut serializer)?;
		println!();
		return Ok(());
	}
	let mut table = Table {
		columns: vec![
			Column {
				align: Alignment::Left,
				values: vec!["proto".to_string()],
			},
			Column {
				align: Alignment::Left,
				values: vec!["state".to_string()],
			},
			Column {
				align: Alignment::Port,
				values: vec!["local address:port".to_string()],
			},
			Column {
				align: Alignment::Port,
				values: vec!["peer address:port".to_string()],
			},
			Column {
				align: Alignment::Left,
				values: vec!["user".to_string()],
			},
			Column {
				align: Alignment::Left,
				values: vec!["process".to_string()],
			},
		],
	};
	for entry in &entries {
		table.columns[0].values.push(entry.protocol.to_string());
		table.columns[1].values.push(entry.state.to_string());
		table.columns[2].values.push(entry.from.to_string());
		table.columns[3].values.push(entry.to.to_string());
		table.columns[4].values.push(entry.user.to_string());
		table.columns[5].values.push(
			entry
				.processes
				.iter()
				.map(|p| format!("{p}"))
				.collect::<Vec<_>>()
				.join(","),
		);
	}
	table.print();
	Ok(())
}
