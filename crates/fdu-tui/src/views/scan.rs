use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, OpState};

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Scan — [s/Enter] run, [d] deep scan (includes bad sectors) ");

    match &app.scan_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Full device scan — filesystem, hardware, and security in one pass.",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from("  Phase 1: Filesystem Validation"),
                    Line::from("    Boot sector, FAT integrity, cluster chains, dirty flags,"),
                    Line::from("    backup sector comparison, cross-links, orphan chains"),
                    Line::from(""),
                    Line::from("  Phase 2: Hardware Diagnostics"),
                    Line::from("    Entropy analysis, debug signature detection,"),
                    Line::from("    fake flash / counterfeit capacity detection"),
                    Line::from(""),
                    Line::from("  Phase 3: Security Audit"),
                    Line::from("    Malware signatures, autorun scripts, BadUSB indicators,"),
                    Line::from("    suspicious deleted files, content analysis"),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(
                            "  [s/Enter]",
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" Quick scan   "),
                        Span::styled(
                            "[d]",
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" Deep scan (adds bad sector test — slower)"),
                    ]),
                ]
            } else {
                vec![
                    Line::from(""),
                    Line::from("  No device selected. Go to [1] Devices and select one first."),
                ]
            };
            frame.render_widget(Paragraph::new(hint).block(block), area);
        }
        OpState::Running(msg) => {
            let lines = vec![
                Line::from(""),
                Line::from(format!("  ... {msg}")),
                Line::from(""),
                Line::from("  Check the external terminal window for live progress."),
                Line::from("  Press [s] to launch again if the window was closed."),
            ];
            let p = Paragraph::new(lines)
                .style(Style::default().fg(Color::Yellow))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Error(e) => {
            let p = Paragraph::new(format!("  Error: {e}"))
                .style(Style::default().fg(Color::Red))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Done(msg) => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {msg}"),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("  Press [s] to scan again, or [3] Repair to fix issues."),
            ];
            frame.render_widget(Paragraph::new(lines).block(block), area);
        }
    }
}
