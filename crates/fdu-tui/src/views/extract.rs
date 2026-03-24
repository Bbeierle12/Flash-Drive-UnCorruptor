use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, OpState};
use crate::ui::{fmt_bytes, severity_style};

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Quarantine Extract — [e/Enter] run ");

    match &app.extract_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                format!(
                    "Press [e] or Enter to extract files (output: {})",
                    app.extract_output_dir
                )
            } else {
                "No device selected. Go to [1] Devices first.".into()
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
        OpState::Done(manifest) => {
            let inner = block.inner(area);
            frame.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(5),
                    Constraint::Min(0),
                ])
                .split(inner);

            // Summary
            let summary = vec![
                Line::from(format!("  Policy: {:?}", manifest.policy)),
                Line::from(format!("  Total bytes: {}", fmt_bytes(manifest.total_bytes()))),
                Line::from(format!("  Files extracted: {}", manifest.files.len())),
                Line::from(format!("  Flagged: {}", manifest.flagged_count())),
                Line::from(format!(
                    "  Quarantine: {}",
                    manifest.quarantine_path.display()
                )),
            ];
            frame.render_widget(Paragraph::new(summary), chunks[0]);

            // File list
            let items: Vec<ListItem> = manifest
                .files
                .iter()
                .map(|f| {
                    let sev_style = severity_style(&f.threat_level);
                    ListItem::new(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(format!("[{:?}]", f.threat_level), sev_style),
                        Span::raw(" "),
                        Span::styled(
                            &f.original_path,
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {}", fmt_bytes(f.size_bytes))),
                        Span::styled(
                            format!("  sha256:{}", &f.sha256[..12]),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            let files_block = Block::default()
                .borders(Borders::TOP)
                .title(format!(" Extracted Files ({}) ", manifest.files.len()));
            frame.render_widget(List::new(items).block(files_block), chunks[1]);
        }
    }
}
