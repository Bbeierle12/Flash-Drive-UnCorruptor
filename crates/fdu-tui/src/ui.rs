use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

use crate::app::{App, Screen};
use crate::views;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),   // body
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    draw_tabs(frame, app, chunks[0]);
    draw_body(frame, app, chunks[1]);
    draw_status_bar(frame, app, chunks[2]);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Screen::ALL
        .iter()
        .map(|s| {
            let style = if *s == app.screen {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(
                format!("[{}] {}", s.key(), s.label()),
                style,
            ))
        })
        .collect();

    let index = Screen::ALL
        .iter()
        .position(|s| *s == app.screen)
        .unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Flash Drive UnCorruptor "),
        )
        .select(index)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    match app.screen {
        Screen::Dashboard => views::dashboard::draw(frame, app, area),
        Screen::Devices => views::devices::draw(frame, app, area),
        Screen::Scan => views::scan::draw(frame, app, area),
        Screen::Repair => views::repair::draw(frame, app, area),
        Screen::Diagnose => views::diagnose::draw(frame, app, area),
        Screen::Audit => views::audit::draw(frame, app, area),
        Screen::Partitions => views::partitions::draw(frame, app, area),
        Screen::Usb => views::usb::draw(frame, app, area),
        Screen::Recover => views::recover::draw(frame, app, area),
        Screen::Extract => views::extract::draw(frame, app, area),
    }
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let device_text = match &app.selected_device {
        Some(d) => format!("Device: {d}"),
        None => "No device selected".into(),
    };

    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit/Back  "),
        Span::styled("0-9", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Navigate  "),
        Span::styled("↑↓/jk", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Scroll  "),
        Span::styled("Enter", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Select/Run  │  "),
        Span::styled(device_text, Style::default().fg(Color::White)),
    ]))
    .style(Style::default().bg(Color::DarkGray));

    frame.render_widget(bar, area);
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Format bytes as a human-readable string.
pub fn fmt_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if bytes >= TIB {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Style a severity value.
pub fn severity_style(sev: &fdu_models::threat::Severity) -> Style {
    match sev {
        fdu_models::threat::Severity::Info => Style::default().fg(Color::Blue),
        fdu_models::threat::Severity::Low => Style::default().fg(Color::Cyan),
        fdu_models::threat::Severity::Medium => Style::default().fg(Color::Yellow),
        fdu_models::threat::Severity::High => Style::default().fg(Color::Red),
        fdu_models::threat::Severity::Critical => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
    }
}
