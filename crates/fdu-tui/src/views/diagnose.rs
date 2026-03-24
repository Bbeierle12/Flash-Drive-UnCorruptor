use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
};

use crate::app::{App, OpState};

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Diagnostics — [d/Enter] run ");

    match &app.diagnose_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                "Press [d] or Enter to run diagnostics on the selected device."
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
                    Constraint::Length(3), // health gauge
                    Constraint::Length(6), // stats
                    Constraint::Min(0),   // bad sector list
                ])
                .split(inner);

            // Health gauge
            let score = report.health_score();
            let gauge_color = if score >= 90.0 {
                Color::Green
            } else if score >= 70.0 {
                Color::Yellow
            } else {
                Color::Red
            };

            let gauge = Gauge::default()
                .block(Block::default().title(" Health Score "))
                .gauge_style(Style::default().fg(gauge_color).bg(Color::DarkGray))
                .percent(score.min(100.0) as u16)
                .label(format!("{score:.1}%"));
            frame.render_widget(gauge, chunks[0]);

            // Stats
            let read_speed = report
                .read_speed_mbps
                .map(|s| format!("{s:.1} MB/s"))
                .unwrap_or_else(|| "N/A".into());
            let write_speed = report
                .write_speed_mbps
                .map(|s| format!("{s:.1} MB/s"))
                .unwrap_or_else(|| "N/A".into());

            let stats = vec![
                Line::from(format!("  Total sectors: {}", report.total_sectors)),
                Line::from(format!("  Bad sectors:   {}", report.bad_sector_count())),
                Line::from(format!("  Read speed:    {read_speed}")),
                Line::from(format!("  Write speed:   {write_speed}")),
                Line::from(format!("  Scan time:     {} ms", report.scan_duration_ms)),
            ];
            frame.render_widget(Paragraph::new(stats), chunks[1]);

            // Bad sectors
            if report.bad_sectors.is_empty() {
                frame.render_widget(
                    Paragraph::new("  No bad sectors detected.")
                        .style(Style::default().fg(Color::Green))
                        .block(Block::default().borders(Borders::TOP).title(" Bad Sectors ")),
                    chunks[2],
                );
            } else {
                let lines: Vec<Line> = report
                    .bad_sectors
                    .iter()
                    .take(50) // cap display
                    .map(|s| {
                        Line::from(Span::styled(
                            format!("  Sector {s}"),
                            Style::default().fg(Color::Red),
                        ))
                    })
                    .collect();
                let title = format!(
                    " Bad Sectors ({}{}) ",
                    report.bad_sector_count(),
                    if report.bad_sector_count() > 50 {
                        " — showing first 50"
                    } else {
                        ""
                    }
                );
                let bad_block = Block::default()
                    .borders(Borders::TOP)
                    .title(title)
                    .title_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
                frame.render_widget(Paragraph::new(lines).block(bad_block), chunks[2]);
            }
        }
    }
}
