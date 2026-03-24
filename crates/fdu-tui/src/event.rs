use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

/// Polls for the next terminal event with a timeout.
/// Returns `None` if no event occurred within `timeout`.
pub fn next_event(timeout: Duration) -> anyhow::Result<Option<Event>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        if event::poll(remaining)? {
            return Ok(Some(event::read()?));
        }
    }
}

/// Check if a key event is the quit key (q or Ctrl+C).
pub fn is_quit(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q'))
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}
