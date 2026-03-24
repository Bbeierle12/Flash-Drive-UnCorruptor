use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, OpState};
use crate::ui::severity_style;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" USB Devices — [u/Enter] scan, ↑↓ navigate ");

    match &app.usb_devices {
        OpState::Idle => {
            frame.render_widget(
                Paragraph::new("Press [u] or Enter to enumerate USB devices.").block(block),
                area,
            );
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
        OpState::Done(devices) => {
            if devices.is_empty() {
                frame.render_widget(
                    Paragraph::new("  No USB devices found.").block(block),
                    area,
                );
                return;
            }

            let items: Vec<ListItem> = devices
                .iter()
                .enumerate()
                .map(|(i, (fp, findings))| {
                    let selected = i == app.usb_list_index;
                    let marker = if selected { "▸ " } else { "  " };

                    let name = fp
                        .product
                        .as_deref()
                        .unwrap_or("Unknown");
                    let vendor = fp
                        .manufacturer
                        .as_deref()
                        .unwrap_or("Unknown");

                    let class_label = if fp.is_mass_storage() {
                        "Mass Storage"
                    } else if fp.has_hid_interface() {
                        "HID"
                    } else if fp.is_composite() {
                        "Composite"
                    } else {
                        "Other"
                    };

                    let finding_summary = if findings.is_empty() {
                        Span::styled(" ✓", Style::default().fg(Color::Green))
                    } else {
                        let worst = findings
                            .iter()
                            .map(|f| &f.severity)
                            .max()
                            .unwrap();
                        Span::styled(
                            format!(" ⚠ {} finding(s)", findings.len()),
                            severity_style(worst),
                        )
                    };

                    let line = Line::from(vec![
                        Span::raw(marker),
                        Span::styled(
                            fp.vid_pid(),
                            if selected {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::Cyan)
                            },
                        ),
                        Span::raw("  "),
                        Span::raw(format!("{vendor} / {name}")),
                        Span::raw("  "),
                        Span::styled(
                            format!("[{class_label}]"),
                            Style::default().fg(Color::DarkGray),
                        ),
                        finding_summary,
                    ]);

                    ListItem::new(line)
                })
                .collect();

            let title = format!(
                " USB Devices ({}) — ↑↓ navigate ",
                devices.len()
            );
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(title));

            frame.render_widget(list, area);
        }
    }
}
