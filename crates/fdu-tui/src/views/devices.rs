use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::app::{App, OpState};
use crate::ui::fmt_bytes;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    match &app.devices {
        OpState::Idle | OpState::Running(_) => {
            let msg = match &app.devices {
                OpState::Running(m) => m.as_str(),
                _ => "Press [r] to scan for devices",
            };
            let p = ratatui::widgets::Paragraph::new(msg)
                .block(Block::default().borders(Borders::ALL).title(" Devices "));
            frame.render_widget(p, area);
        }
        OpState::Error(e) => {
            let p = ratatui::widgets::Paragraph::new(format!("Error: {e}"))
                .style(Style::default().fg(Color::Red))
                .block(Block::default().borders(Borders::ALL).title(" Devices "));
            frame.render_widget(p, area);
        }
        OpState::Done(devs) => {
            let items: Vec<ListItem> = devs
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let selected_marker = if app
                        .selected_device
                        .as_deref()
                        .map(|s| s == d.device_path)
                        .unwrap_or(false)
                    {
                        "★ "
                    } else {
                        "  "
                    };

                    let removable = if d.is_removable { "removable" } else { "internal" };
                    let mount = d
                        .mount_point
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "not mounted".into());
                    let transport = d.transport.as_deref().unwrap_or("?");

                    let line = Line::from(vec![
                        Span::styled(
                            selected_marker,
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(
                            &d.device_path,
                            if i == app.device_list_index {
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                        Span::raw("  "),
                        Span::styled(
                            format!("{:<16}", format!("{} {}", d.vendor.trim(), d.model.trim())),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::raw("  "),
                        Span::raw(format!("{:<10}", fmt_bytes(d.size_bytes))),
                        Span::raw("  "),
                        Span::styled(
                            format!("{removable:<10}"),
                            if d.is_removable {
                                Style::default().fg(Color::Yellow)
                            } else {
                                Style::default().fg(Color::DarkGray)
                            },
                        ),
                        Span::raw(format!("{transport:<5}  ")),
                        Span::styled(mount, Style::default().fg(Color::DarkGray)),
                    ]);

                    ListItem::new(line)
                })
                .collect();

            let title = format!(
                " Devices ({}) — ↑↓ navigate, Enter select, r refresh ",
                devs.len()
            );
            let list = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title),
            );

            frame.render_widget(list, area);
        }
    }
}
