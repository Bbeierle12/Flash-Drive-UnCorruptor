use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use crate::app::{App, OpState};
use crate::ui::fmt_bytes;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Partition Layout — [p/Enter] analyze ");

    match &app.partitions_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                "Press [p] or Enter to analyze partition layout."
            } else {
                "No device selected. Go to [1] Devices first."
            };
            frame.render_widget(Paragraph::new(hint).block(block), area);
        }
        OpState::Running(msg) => {
            let p = Paragraph::new(format!("⏳ {msg}"))
                .style(Style::default().fg(Color::Yellow))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Error(e) => {
            let p = Paragraph::new(format!("✗ {e}"))
                .style(Style::default().fg(Color::Red))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Done(layout) => {
            let inner = block.inner(area);
            frame.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(4), // summary
                    Constraint::Min(0),   // table
                ])
                .split(inner);

            let summary = vec![
                Line::from(format!("  Scheme: {:?}", layout.scheme)),
                Line::from(format!(
                    "  Total: {} sectors ({} sector size)",
                    layout.total_sectors, layout.sector_size
                )),
                Line::from(format!(
                    "  Allocated: {} | Unallocated: {}",
                    fmt_bytes(layout.allocated_bytes()),
                    fmt_bytes(layout.unallocated_bytes())
                )),
            ];
            frame.render_widget(Paragraph::new(summary), chunks[0]);

            // Partition table
            let header = Row::new(vec!["#", "Type", "Label", "Start LBA", "End LBA", "Size", "Flags"])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );

            let rows: Vec<Row> = layout
                .partitions
                .iter()
                .map(|p| {
                    let flags = [
                        if p.flags.bootable { "boot" } else { "" },
                        if p.flags.system { "sys" } else { "" },
                        if p.flags.hidden { "hidden" } else { "" },
                    ]
                    .iter()
                    .filter(|f| !f.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(",");

                    Row::new(vec![
                        format!("{}", p.index),
                        p.type_label.clone(),
                        p.label.clone().unwrap_or_default(),
                        format!("{}", p.start_lba),
                        format!("{}", p.end_lba),
                        fmt_bytes(p.size_bytes),
                        flags,
                    ])
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Length(3),
                    Constraint::Length(20),
                    Constraint::Length(16),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Min(8),
                ],
            )
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(format!(" Partitions ({}) ", layout.partitions.len())),
            );

            frame.render_widget(table, chunks[1]);
        }
    }
}
