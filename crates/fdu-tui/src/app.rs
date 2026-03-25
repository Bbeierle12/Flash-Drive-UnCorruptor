use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::{event, ui};

/// Platform-aware default extraction directory.
///
/// Checks `FDU_EXTRACT_DIR` env var first, then falls back to
/// `$XDG_DATA_HOME/fdu-extract` (Linux) or `~/.local/share/fdu-extract`.
fn default_extract_dir() -> String {
    if let Ok(dir) = std::env::var("FDU_EXTRACT_DIR") {
        return dir;
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return format!("{}/fdu-extract", xdg);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return format!("{}/.local/share/fdu-extract", home.to_string_lossy());
    }
    // Ultimate fallback
    "/tmp/fdu-extract".into()
}

// ── Screens / Views ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Devices,
    Scan,
    Repair,
    Partitions,
    Usb,
    Recover,
    Extract,
}

impl Screen {
    pub const ALL: &[Screen] = &[
        Screen::Dashboard,
        Screen::Devices,
        Screen::Scan,
        Screen::Repair,
        Screen::Partitions,
        Screen::Usb,
        Screen::Recover,
        Screen::Extract,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Devices => "Devices",
            Screen::Scan => "Scan",
            Screen::Repair => "Repair",
            Screen::Partitions => "Partitions",
            Screen::Usb => "USB",
            Screen::Recover => "Recover",
            Screen::Extract => "Extract",
        }
    }

    pub fn key(self) -> char {
        match self {
            Screen::Dashboard => '0',
            Screen::Devices => '1',
            Screen::Scan => '2',
            Screen::Repair => '3',
            Screen::Partitions => '4',
            Screen::Usb => '5',
            Screen::Recover => '6',
            Screen::Extract => '7',
        }
    }
}

// ── Device data cached from enumeration ─────────────────────────────

use fdu_device_enum::EnumeratedDevice;

// ── Per-screen state holders ────────────────────────────────────────

use fdu_core::models::RecoverableFile;
use fdu_disk::layout::DiskLayout;
use fdu_models::extraction::ExtractionManifest;
use fdu_models::usb::UsbFingerprint;

/// Holds the result of an operation that can be idle, running, done, or failed.
#[derive(Debug)]
pub enum OpState<T> {
    Idle,
    Running(String),
    Done(T),
    Error(String),
}

impl<T> Default for OpState<T> {
    fn default() -> Self {
        OpState::Idle
    }
}

// ── Application state ───────────────────────────────────────────────

pub struct App {
    pub running: bool,
    pub screen: Screen,

    // Device list
    pub devices: OpState<Vec<EnumeratedDevice>>,
    pub device_list_index: usize,

    // Selected device path (set by the user from Devices screen)
    pub selected_device: Option<String>,

    // Scan (unified: filesystem + hardware diagnostics + security audit)
    pub scan_result: OpState<String>,

    // Repair
    pub repair_result: OpState<String>,

    // Partitions
    pub partitions_result: OpState<DiskLayout>,

    // USB
    pub usb_devices: OpState<Vec<(UsbFingerprint, Vec<fdu_models::threat::Finding>)>>,
    pub usb_list_index: usize,

    // Recover
    pub recover_result: OpState<Vec<RecoverableFile>>,

    // Extract
    pub extract_output_dir: String,
    pub extract_result: OpState<ExtractionManifest>,

    // Scrollable finding list index (shared by usb)
    pub finding_index: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            screen: Screen::Dashboard,
            devices: OpState::Idle,
            device_list_index: 0,
            selected_device: None,
            scan_result: OpState::Idle,
            repair_result: OpState::Idle,
            partitions_result: OpState::Idle,
            usb_devices: OpState::Idle,
            usb_list_index: 0,
            recover_result: OpState::Idle,
            extract_output_dir: default_extract_dir(),
            extract_result: OpState::Idle,
            finding_index: 0,
        }
    }

    pub fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
        // Auto-enumerate devices at startup
        self.enumerate_devices();

        while self.running {
            terminal.draw(|frame| ui::draw(frame, self))?;

            if let Some(ev) = event::next_event(Duration::from_millis(100))? {
                if let Event::Key(key) = ev {
                    self.handle_key(key);
                }
            }
        }
        Ok(())
    }

    // ── Key handling ────────────────────────────────────────────────

    fn handle_key(&mut self, key: KeyEvent) {
        // Global: quit (q or Ctrl+C)
        if event::is_quit(&key) {
            if self.screen == Screen::Dashboard {
                self.running = false;
                return;
            }
            // Go back to dashboard from any other screen
            self.screen = Screen::Dashboard;
            return;
        }

        // Esc: go back to dashboard from any screen
        if key.code == KeyCode::Esc {
            self.screen = Screen::Dashboard;
            return;
        }

        // Global: Tab / BackTab / Arrow keys cycle through screens
        match key.code {
            KeyCode::Tab | KeyCode::Right => {
                let idx = Screen::ALL.iter().position(|s| *s == self.screen).unwrap_or(0);
                self.screen = Screen::ALL[(idx + 1) % Screen::ALL.len()];
                self.finding_index = 0;
                return;
            }
            KeyCode::BackTab | KeyCode::Left => {
                let idx = Screen::ALL.iter().position(|s| *s == self.screen).unwrap_or(0);
                self.screen = Screen::ALL[(idx + Screen::ALL.len() - 1) % Screen::ALL.len()];
                self.finding_index = 0;
                return;
            }
            _ => {}
        }

        // Global: number keys navigate
        if let KeyCode::Char(c) = key.code {
            for s in Screen::ALL {
                if s.key() == c {
                    self.screen = *s;
                    self.finding_index = 0;
                    return;
                }
            }
        }

        // Delegate to per-screen handler
        match self.screen {
            Screen::Dashboard => self.handle_dashboard_key(key),
            Screen::Devices => self.handle_devices_key(key),
            Screen::Scan => self.handle_scan_key(key),
            Screen::Repair => self.handle_repair_key(key),
            Screen::Partitions => self.handle_partitions_key(key),
            Screen::Usb => self.handle_usb_key(key),
            Screen::Recover => self.handle_recover_key(key),
            Screen::Extract => self.handle_extract_key(key),
        }
    }

    fn handle_dashboard_key(&mut self, key: KeyEvent) {
        if let KeyCode::Char('r') = key.code {
            self.enumerate_devices();
        }
    }

    fn handle_devices_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.device_list_index = self.device_list_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let OpState::Done(ref devs) = self.devices {
                    if self.device_list_index + 1 < devs.len() {
                        self.device_list_index += 1;
                    }
                }
            }
            KeyCode::Enter => {
                if let OpState::Done(ref devs) = self.devices {
                    if let Some(dev) = devs.get(self.device_list_index) {
                        self.selected_device = Some(dev.device_path.clone());
                    }
                }
            }
            KeyCode::Char('r') => self.enumerate_devices(),
            _ => {}
        }
    }

    fn handle_scan_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('s') => self.run_scan(false),
            KeyCode::Char('d') => self.run_scan(true), // deep scan with bad sectors
            _ => {}
        }
    }

    fn handle_repair_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('r') => self.run_repair(),
            _ => {}
        }
    }

    fn handle_partitions_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('p') => self.run_partitions(),
            _ => {}
        }
    }

    fn handle_usb_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('u') => self.run_usb_enumerate(),
            KeyCode::Up | KeyCode::Char('k') => {
                self.usb_list_index = self.usb_list_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let OpState::Done(ref devs) = self.usb_devices {
                    if self.usb_list_index + 1 < devs.len() {
                        self.usb_list_index += 1;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_recover_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('r') => self.run_recover(),
            _ => {}
        }
    }

    fn handle_extract_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('e') => self.run_extract(),
            _ => {}
        }
    }

    // ── Operations ──────────────────────────────────────────────────

    fn enumerate_devices(&mut self) {
        self.devices = OpState::Running("Enumerating devices...".into());
        match fdu_device_enum::enumerate_devices() {
            Ok(devs) => {
                self.device_list_index = 0;
                self.devices = OpState::Done(devs);
            }
            Err(e) => self.devices = OpState::Error(format!("{e}")),
        }
    }

    /// Helper: open the selected device.
    fn open_device(&self) -> Result<Box<dyn fdu_core::device::Device>, String> {
        let path = self
            .selected_device
            .as_deref()
            .ok_or_else(|| "No device selected — go to Devices [1] and press Enter".to_string())?;

        #[cfg(target_os = "linux")]
        {
            use fdu_core::device::linux::LinuxDevice;
            if path.starts_with("/dev/") {
                LinuxDevice::open(path, false)
                    .map(|d| Box::new(d) as Box<dyn fdu_core::device::Device>)
                    .map_err(|e| format!("{e}"))
            } else {
                LinuxDevice::open_image(path)
                    .map(|d| Box::new(d) as Box<dyn fdu_core::device::Device>)
                    .map_err(|e| format!("{e}"))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err("Direct device access is only supported on Linux".into())
        }
    }

    fn run_scan(&mut self, deep: bool) {
        let path = match &self.selected_device {
            Some(p) => p.clone(),
            None => {
                self.scan_result =
                    OpState::Error("No device selected — go to Devices [1] and press Enter".into());
                return;
            }
        };

        let fdu_bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fdu")))
            .unwrap_or_else(|| PathBuf::from("fdu"));

        let deep_flag = if deep { " --deep" } else { "" };

        let terminal_cmd = find_terminal_emulator();
        let child = std::process::Command::new(&terminal_cmd)
            .args(terminal_exec_args(
                &terminal_cmd,
                &format!(
                    "echo '=== Flash Drive UnCorruptor — Full Scan ===' && echo && \
                     {} scan {}{}; \
                     echo && echo 'Press Enter to close...' && read",
                    shell_escape(&fdu_bin.to_string_lossy()),
                    shell_escape(&path),
                    deep_flag,
                ),
            ))
            .spawn();

        let mode = if deep { "Deep scan" } else { "Scan" };
        match child {
            Ok(_) => {
                self.scan_result = OpState::Running(format!(
                    "{} running in external terminal for {}",
                    mode, path
                ));
            }
            Err(e) => {
                self.scan_result = OpState::Error(format!(
                    "Failed to open terminal (tried '{}'): {}. \
                     Run manually: fdu scan {:?}{}",
                    terminal_cmd, e, path, deep_flag
                ));
            }
        }
    }

    fn run_repair(&mut self) {
        let path = match &self.selected_device {
            Some(p) => p.clone(),
            None => {
                self.repair_result =
                    OpState::Error("No device selected — go to Devices [1] and press Enter".into());
                return;
            }
        };

        let fdu_bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fdu")))
            .unwrap_or_else(|| PathBuf::from("fdu"));

        let terminal_cmd = find_terminal_emulator();
        let child = std::process::Command::new(&terminal_cmd)
            .args(terminal_exec_args(
                &terminal_cmd,
                &format!(
                    "echo '=== Flash Drive UnCorruptor — REPAIR ===' && \
                     echo && \
                     echo 'WARNING: This will WRITE to the device.' && \
                     echo 'Press Ctrl+C to cancel, or Enter to proceed...' && \
                     read && \
                     sudo {} repair {} --unsafe-mode; \
                     echo && echo 'Press Enter to close...' && read",
                    shell_escape(&fdu_bin.to_string_lossy()),
                    shell_escape(&path),
                ),
            ))
            .spawn();

        match child {
            Ok(_) => {
                self.repair_result = OpState::Running(format!(
                    "Repair running in external terminal for {}",
                    path
                ));
            }
            Err(e) => {
                self.repair_result = OpState::Error(format!(
                    "Failed to open terminal (tried '{}'): {}. \
                     Run manually: sudo fdu repair {:?} --unsafe-mode",
                    terminal_cmd, e, path
                ));
            }
        }
    }

    fn run_partitions(&mut self) {
        self.partitions_result = OpState::Running("Analyzing partitions...".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.partitions_result = OpState::Error(e);
                return;
            }
        };

        match fdu_disk::analyze_partitions(device.as_ref()) {
            Ok(layout) => self.partitions_result = OpState::Done(layout),
            Err(e) => self.partitions_result = OpState::Error(format!("{e}")),
        }
    }

    fn run_usb_enumerate(&mut self) {
        self.usb_devices = OpState::Running("Scanning USB bus...".into());
        match fdu_usb::enumerate_usb_devices() {
            Ok(fps) => {
                let with_findings: Vec<_> = fps
                    .into_iter()
                    .map(|fp| {
                        let findings = fdu_usb::detect_badusb(&fp);
                        (fp, findings)
                    })
                    .collect();
                self.usb_list_index = 0;
                self.usb_devices = OpState::Done(with_findings);
            }
            Err(e) => self.usb_devices = OpState::Error(format!("{e}")),
        }
    }

    fn run_recover(&mut self) {
        self.recover_result = OpState::Running("Scanning for recoverable files...".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.recover_result = OpState::Error(e);
                return;
            }
        };

        match fdu_core::recovery::scan_signatures(device.as_ref(), &[], None) {
            Ok(files) => self.recover_result = OpState::Done(files),
            Err(e) => self.recover_result = OpState::Error(format!("{e}")),
        }
    }

    fn run_extract(&mut self) {
        self.extract_result = OpState::Running("Extracting files...".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.extract_result = OpState::Error(e);
                return;
            }
        };

        let output = PathBuf::from(&self.extract_output_dir);
        match fdu_extract::extract(
            device.as_ref(),
            fdu_models::extraction::ExtractionPolicy::VerifiedOnly,
            &output,
            None,
        ) {
            Ok(manifest) => self.extract_result = OpState::Done(manifest),
            Err(e) => self.extract_result = OpState::Error(format!("{e}")),
        }
    }
}

/// Find a terminal emulator available on the system.
fn find_terminal_emulator() -> String {
    let candidates = [
        "x-terminal-emulator", // Debian/Ubuntu default
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "lxterminal",
        "alacritty",
        "kitty",
        "wezterm",
        "foot",
        "xterm",
    ];

    for term in &candidates {
        if which_exists(term) {
            return term.to_string();
        }
    }

    "xterm".to_string()
}

/// Build the correct exec arguments for the detected terminal emulator.
fn terminal_exec_args(terminal: &str, command: &str) -> Vec<String> {
    let base = terminal.rsplit('/').next().unwrap_or(terminal);
    match base {
        "gnome-terminal" => vec![
            "--".into(),
            "bash".into(),
            "-c".into(),
            command.into(),
        ],
        "konsole" => vec!["-e".into(), "bash".into(), "-c".into(), command.into()],
        "alacritty" => vec!["-e".into(), "bash".into(), "-c".into(), command.into()],
        "kitty" => vec!["bash".into(), "-c".into(), command.into()],
        "wezterm" => vec!["start".into(), "--".into(), "bash".into(), "-c".into(), command.into()],
        "foot" => vec!["-e".into(), "bash".into(), "-c".into(), command.into()],
        // xterm, xfce4-terminal, mate-terminal, lxterminal, x-terminal-emulator
        _ => vec!["-e".into(), format!("bash -c {}", shell_escape(command))],
    }
}

/// Check if a command exists on PATH.
fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Escape a string for use as a single shell argument.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
