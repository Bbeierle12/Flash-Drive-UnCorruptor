use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, OpState};
use crate::ui::fmt_bytes;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" File Recovery (scan only) — [r/Enter] scan ");

    match &app.recover_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                "Press [r] or Enter to scan for recoverable files."
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
        OpState::Done(files) => {
            if files.is_empty() {
                frame.render_widget(
                    Paragraph::new("  No recoverable files found.")
                        .style(Style::default().fg(Color::Yellow))
                        .block(block),
                    area,
                );
                return;
            }

            let items: Vec<ListItem> = files
                .iter()
                .map(|f| {
                    let name = f
                        .original_name
                        .as_deref()
                        .unwrap_or("<unknown>");
                    let confidence_color = if f.confidence >= 0.8 {
                        Color::Green
                    } else if f.confidence >= 0.5 {
                        Color::Yellow
                    } else {
                        Color::Red
                    };

                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!("  {:<6}", f.file_type),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {name:<24}")),
                        Span::raw(format!("  {:<10}", fmt_bytes(f.estimated_size))),
                        Span::styled(
                            format!("  {:.0}% conf", f.confidence * 100.0),
                            Style::default().fg(confidence_color),
                        ),
                        Span::styled(
                            format!("  @ offset 0x{:X}", f.offset),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            let title = format!(
                " Recoverable Files ({}) ",
                files.len()
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
