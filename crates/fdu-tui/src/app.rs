use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::{event, ui};

// ── Screens / Views ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Devices,
    Scan,
    Diagnose,
    Audit,
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
        Screen::Diagnose,
        Screen::Audit,
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
            Screen::Diagnose => "Diagnose",
            Screen::Audit => "Audit",
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
            Screen::Diagnose => '3',
            Screen::Audit => '4',
            Screen::Partitions => '5',
            Screen::Usb => '6',
            Screen::Recover => '7',
            Screen::Extract => '8',
        }
    }
}

// ── Device data cached from enumeration ─────────────────────────────

use fdu_device_enum::EnumeratedDevice;

// ── Per-screen state holders ────────────────────────────────────────

use fdu_core::models::{DiagnosticReport, FsType, RecoverableFile, ValidationReport};
use fdu_disk::layout::DiskLayout;
use fdu_models::extraction::ExtractionManifest;
use fdu_models::threat::ThreatReport;
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

    // Scan
    pub scan_result: OpState<ValidationReport>,

    // Diagnose
    pub diagnose_result: OpState<DiagnosticReport>,

    // Audit
    pub audit_result: OpState<ThreatReport>,

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

    // Scrollable finding list index (shared by audit/usb)
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
            diagnose_result: OpState::Idle,
            audit_result: OpState::Idle,
            partitions_result: OpState::Idle,
            usb_devices: OpState::Idle,
            usb_list_index: 0,
            recover_result: OpState::Idle,
            extract_output_dir: "/tmp/fdu-extract".into(),
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
        // Global: quit
        if event::is_quit(&key) {
            if self.screen == Screen::Dashboard {
                self.running = false;
                return;
            }
            // Go back to dashboard from any other screen
            self.screen = Screen::Dashboard;
            return;
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
            Screen::Diagnose => self.handle_diagnose_key(key),
            Screen::Audit => self.handle_audit_key(key),
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
            KeyCode::Enter | KeyCode::Char('s') => self.run_scan(),
            _ => {}
        }
    }

    fn handle_diagnose_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('d') => self.run_diagnose(),
            _ => {}
        }
    }

    fn handle_audit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('a') => self.run_audit(),
            KeyCode::Up | KeyCode::Char('k') => {
                self.finding_index = self.finding_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let OpState::Done(ref report) = self.audit_result {
                    if self.finding_index + 1 < report.findings.len() {
                        self.finding_index += 1;
                    }
                }
            }
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

    // ── Operations (synchronous — all core APIs are sync) ───────────

    fn enumerate_devices(&mut self) {
        self.devices = OpState::Running("Enumerating devices…".into());
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

    fn run_scan(&mut self) {
        self.scan_result = OpState::Running("Scanning filesystem…".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.scan_result = OpState::Error(e);
                return;
            }
        };

        let fs_type = match fdu_core::fs::detect_filesystem(device.as_ref()) {
            Ok(t) => t,
            Err(e) => {
                self.scan_result = OpState::Error(format!("{e}"));
                return;
            }
        };

        match fs_type {
            FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
                use fdu_core::fs::fat32::Fat32Fs;
                use fdu_core::fs::FileSystemOps;
                match Fat32Fs::new(device.as_ref()) {
                    Ok(fs) => match fs.validate() {
                        Ok(report) => self.scan_result = OpState::Done(report),
                        Err(e) => self.scan_result = OpState::Error(format!("{e}")),
                    },
                    Err(e) => self.scan_result = OpState::Error(format!("{e}")),
                }
            }
            other => {
                self.scan_result = OpState::Error(format!(
                    "Filesystem '{other}' scanning not yet supported. Currently: FAT12/16/32."
                ));
            }
        }
    }

    fn run_diagnose(&mut self) {
        self.diagnose_result = OpState::Running("Running diagnostics…".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.diagnose_result = OpState::Error(e);
                return;
            }
        };

        match fdu_core::diagnostics::scan_bad_sectors(device.as_ref(), None) {
            Ok(report) => self.diagnose_result = OpState::Done(report),
            Err(e) => self.diagnose_result = OpState::Error(format!("{e}")),
        }
    }

    fn run_audit(&mut self) {
        self.audit_result = OpState::Running("Running security audit…".into());
        let device = match self.open_device() {
            Ok(d) => d,
            Err(e) => {
                self.audit_result = OpState::Error(e);
                return;
            }
        };

        let config = fdu_audit::AuditConfig::default();
        let mut engine = fdu_audit::AuditEngine::new(config);
        engine.register_defaults();

        match engine.scan(device.as_ref(), None) {
            Ok(report) => {
                self.finding_index = 0;
                self.audit_result = OpState::Done(report);
            }
            Err(e) => self.audit_result = OpState::Error(format!("{e}")),
        }
    }

    fn run_partitions(&mut self) {
        self.partitions_result = OpState::Running("Analyzing partitions…".into());
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
        self.usb_devices = OpState::Running("Scanning USB bus…".into());
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
        self.recover_result = OpState::Running("Scanning for recoverable files…".into());
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
        self.extract_result = OpState::Running("Extracting files…".into());
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
