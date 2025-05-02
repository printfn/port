pub struct Table {
	pub columns: Vec<Column>,
}

pub struct Column {
	pub values: Vec<String>,
	pub align: Alignment,
}

#[derive(PartialEq, Eq)]
pub enum Alignment {
	Left,
	Port,
}

fn visual_width(s: &str) -> usize {
	unicode_width::UnicodeWidthStr::width(s)
}

impl Table {
	pub fn print(&mut self) {
		for c in self.columns.iter_mut() {
			let mut max_width = 0;
			let mut max_width_before_port = 0;
			let mut max_width_after_port = 0;
			for v in &c.values {
				max_width = max_width.max(visual_width(v));
				if c.align == Alignment::Port {
					if let Some((a, b)) = v.rsplit_once(':') {
						max_width_before_port = max_width_before_port.max(visual_width(a));
						max_width_after_port = max_width_after_port.max(visual_width(b));
					}
				}
			}
			for v in &mut c.values {
				match c.align {
					Alignment::Left => v.push_str(&" ".repeat(max_width - visual_width(v))),
					Alignment::Port => {
						if let Some((a, b)) = v
							.rsplit_once(':')
							.map(|(a, b)| (visual_width(a), visual_width(b)))
						{
							v.push_str(&" ".repeat(max_width_after_port - b));
							v.insert_str(0, &" ".repeat(max_width_before_port - a));
						}
						if visual_width(v) < max_width {
							v.push_str(&" ".repeat(max_width - visual_width(v)));
						}
					}
				}
			}
		}
		for ri in 0..self.columns[0].values.len() {
			for (i, c) in self.columns.iter_mut().enumerate() {
				if i > 0 {
					print!(" ");
				}
				print!("{}", c.values[ri]);
			}
			println!();
		}
	}
}
