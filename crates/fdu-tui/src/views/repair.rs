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
        .title(" Repair — [r/Enter] run ");

    match &app.repair_result {
        OpState::Idle => {
            let hint = if app.selected_device.is_some() {
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  WARNING: Repair writes directly to the device.",
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from("  This will attempt to fix detected filesystem corruption:"),
                    Line::from("    • Boot signature restoration (from backup sector)"),
                    Line::from("    • FAT1/FAT2 resynchronization"),
                    Line::from("    • Circular cluster chain breaking"),
                    Line::from("    • Cross-linked cluster repair"),
                    Line::from("    • Orphan cluster chain cleanup"),
                    Line::from("    • FSInfo free cluster count recalculation"),
                    Line::from("    • Backup boot sector restoration"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Press [r] or Enter to open repair in a new terminal.",
                        Style::default().fg(Color::Green),
                    )),
                    Line::from("  You will be prompted for confirmation before any writes."),
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
                Line::from(format!("  ⏳ {msg}")),
                Line::from(""),
                Line::from("  Check the external terminal window for progress."),
                Line::from("  Press [r] to launch again if the window was closed."),
            ];
            let p = Paragraph::new(lines)
                .style(Style::default().fg(Color::Yellow))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Error(e) => {
            let p = Paragraph::new(format!("  ✗ {e}"))
                .style(Style::default().fg(Color::Red))
                .block(block);
            frame.render_widget(p, area);
        }
        OpState::Done(msg) => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  ✓ {msg}"),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("  Run [2] Scan to verify the repair."),
            ];
            frame.render_widget(Paragraph::new(lines).block(block), area);
        }
    }
}
