use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, OpState};
use crate::ui::fmt_bytes;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filesystem Scan — [s/Enter] run ");

    match &app.scan_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                "Press [s] or Enter to scan the selected device."
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
                    Constraint::Length(6),
                    Constraint::Min(0),
                ])
                .split(inner);

            // Summary
            let healthy_icon = if report.is_healthy() { "✓ Healthy" } else { "✗ Issues found" };
            let healthy_style = if report.is_healthy() {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            };

            let summary = vec![
                Line::from(vec![
                    Span::raw("  Status: "),
                    Span::styled(healthy_icon, healthy_style),
                ]),
                Line::from(format!("  Filesystem: {:?}", report.fs_type)),
                Line::from(format!(
                    "  Size: {} (used: {}, free: {})",
                    fmt_bytes(report.metadata.total_bytes),
                    fmt_bytes(report.metadata.used_bytes),
                    fmt_bytes(report.metadata.free_bytes),
                )),
                Line::from(format!(
                    "  Clusters: {} (size: {} B)",
                    report.metadata.total_clusters, report.metadata.cluster_size
                )),
                Line::from(format!("  Scan time: {} ms", report.scan_duration_ms)),
            ];
            frame.render_widget(Paragraph::new(summary), chunks[0]);

            // Issues
            if report.issues.is_empty() {
                frame.render_widget(
                    Paragraph::new("  No issues found.")
                        .style(Style::default().fg(Color::Green)),
                    chunks[1],
                );
            } else {
                let lines: Vec<Line> = report
                    .issues
                    .iter()
                    .map(|issue| {
                        let sev_color = match issue.severity {
                            fdu_core::models::Severity::Info => Color::Blue,
                            fdu_core::models::Severity::Warning => Color::Yellow,
                            fdu_core::models::Severity::Error => Color::Red,
                            fdu_core::models::Severity::Critical => Color::Red,
                        };
                        let repairable = if issue.repairable { " [repairable]" } else { "" };
                        Line::from(vec![
                            Span::styled(
                                format!("  [{:?}] ", issue.severity),
                                Style::default().fg(sev_color),
                            ),
                            Span::raw(format!("{}: {}", issue.code, issue.message)),
                            Span::styled(repairable, Style::default().fg(Color::DarkGray)),
                        ])
                    })
                    .collect();
                let title = format!(
                    " Issues: {} errors, {} warnings ",
                    report.error_count(),
                    report.warning_count()
                );
                let issues_block = Block::default().borders(Borders::TOP).title(title);
                frame.render_widget(Paragraph::new(lines).block(issues_block), chunks[1]);
            }
        }
    }
}
