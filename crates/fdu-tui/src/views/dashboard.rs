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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(8),  // banner
            Constraint::Length(6),  // device summary
            Constraint::Min(0),    // quick actions
        ])
        .split(area);

    draw_banner(frame, chunks[0]);
    draw_device_summary(frame, app, chunks[1]);
    draw_quick_actions(frame, chunks[2]);
}

fn draw_banner(frame: &mut Frame, area: Rect) {
    let banner = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ╔═══════════════════════════════════════════════╗",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "  ║     Flash Drive UnCorruptor  v0.1.0          ║",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ║     USB Security Audit & Recovery Toolkit     ║",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "  ╚═══════════════════════════════════════════════╝",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
    ];
    frame.render_widget(Paragraph::new(banner), area);
}

fn draw_device_summary(frame: &mut Frame, app: &App, area: Rect) {
    let content = match &app.devices {
        OpState::Idle => vec![Line::from("  Press [1] to view devices, or [r] to refresh.")],
        OpState::Running(msg) => vec![Line::from(Span::styled(
            format!("  ⏳ {msg}"),
            Style::default().fg(Color::Yellow),
        ))],
        OpState::Error(e) => vec![Line::from(Span::styled(
            format!("  ✗ {e}"),
            Style::default().fg(Color::Red),
        ))],
        OpState::Done(devs) => {
            let removable = devs.iter().filter(|d| d.is_removable).count();
            let total_size: u64 = devs.iter().map(|d| d.size_bytes).sum();
            let selected = app
                .selected_device
                .as_deref()
                .unwrap_or("none — go to [1] Devices");
            vec![
                Line::from(format!(
                    "  Devices: {} found ({} removable, {} total)",
                    devs.len(),
                    removable,
                    fmt_bytes(total_size)
                )),
                Line::from(format!("  Selected: {selected}")),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press [r] to refresh devices",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Connected Devices ");
    frame.render_widget(Paragraph::new(content).block(block), area);
}

fn draw_quick_actions(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Quick Actions:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [1] ", Style::default().fg(Color::Yellow)),
            Span::raw("Devices   — List & select drives"),
        ]),
        Line::from(vec![
            Span::styled("  [2] ", Style::default().fg(Color::Yellow)),
            Span::raw("Scan      — Filesystem integrity check"),
        ]),
        Line::from(vec![
            Span::styled("  [3] ", Style::default().fg(Color::Yellow)),
            Span::raw("Diagnose  — Bad sectors & health score"),
        ]),
        Line::from(vec![
            Span::styled("  [4] ", Style::default().fg(Color::Yellow)),
            Span::raw("Audit     — Full security audit (5 phases)"),
        ]),
        Line::from(vec![
            Span::styled("  [5] ", Style::default().fg(Color::Yellow)),
            Span::raw("Partitions — MBR/GPT layout analysis"),
        ]),
        Line::from(vec![
            Span::styled("  [6] ", Style::default().fg(Color::Yellow)),
            Span::raw("USB       — USB device inspection & BadUSB detection"),
        ]),
        Line::from(vec![
            Span::styled("  [7] ", Style::default().fg(Color::Yellow)),
            Span::raw("Recover   — Scan for deleted/lost files"),
        ]),
        Line::from(vec![
            Span::styled("  [8] ", Style::default().fg(Color::Yellow)),
            Span::raw("Extract   — Quarantine-based file extraction"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Select a device first [1], then run any operation.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Navigation ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
