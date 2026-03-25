use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, OpState};
use crate::ui::severity_style;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Security Audit — [a/Enter] run, ↑↓ scroll findings ");

    match &app.audit_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                "Press [a] or Enter to run a full security audit."
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
        OpState::Done(report) => {
            let inner = block.inner(area);
            frame.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(5), // summary
                    Constraint::Min(0),   // findings list
                ])
                .split(inner);

            // Summary
            let risk_style = severity_style(&report.overall_risk);
            let mount_style = if report.safe_to_mount {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            };

            let summary = vec![
                Line::from(vec![
                    Span::raw("  Overall risk: "),
                    Span::styled(format!("{:?}", report.overall_risk), risk_style),
                ]),
                Line::from(vec![
                    Span::raw("  Safe to mount: "),
                    Span::styled(
                        if report.safe_to_mount { "YES" } else { "NO" },
                        mount_style,
                    ),
                ]),
                Line::from(format!("  Total findings: {}", report.findings.len())),
                Line::from(format!(
                    "  Scan duration: {:.1}s",
                    report.scan_duration.as_secs_f64()
                )),
            ];
            frame.render_widget(Paragraph::new(summary), chunks[0]);

            // Findings list
            if report.findings.is_empty() {
                frame.render_widget(
                    Paragraph::new("  No findings — device looks clean.")
                        .style(Style::default().fg(Color::Green))
                        .block(Block::default().borders(Borders::TOP).title(" Findings ")),
                    chunks[1],
                );
            } else {
                let items: Vec<ListItem> = report
                    .findings
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let marker = if i == app.finding_index { "▸ " } else { "  " };
                        let sev_style = severity_style(&f.severity);

                        let mut spans = vec![
                            Span::raw(marker),
                            Span::styled(format!("[{:?}]", f.severity), sev_style),
                            Span::raw(" "),
                            Span::styled(
                                &f.title,
                                if i == app.finding_index {
                                    Style::default().add_modifier(Modifier::BOLD)
                                } else {
                                    Style::default()
                                },
                            ),
                            Span::styled(
                                format!("  ({})", f.detector),
                                Style::default().fg(Color::DarkGray),
                            ),
                        ];

                        // Show description for selected finding
                        if i == app.finding_index {
                            spans.clear();
                            spans.push(Span::raw("▸ "));
                            spans.push(Span::styled(format!("[{:?}]", f.severity), sev_style));
                            spans.push(Span::raw(" "));
                            spans.push(Span::styled(
                                &f.title,
                                Style::default().add_modifier(Modifier::BOLD),
                            ));
                        }

                        ListItem::new(Line::from(spans))
                    })
                    .collect();

                let findings_block = Block::default()
                    .borders(Borders::TOP)
                    .title(format!(" Findings ({}) ", report.findings.len()));
                frame.render_widget(List::new(items).block(findings_block), chunks[1]);
            }
        }
    }
}
