//! Linux block device access via direct file descriptor I/O.

use crate::device::traits::Device;
use crate::errors::{Error, Result};
use crate::models::FsType;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

/// A Linux block device opened for raw I/O.
pub struct LinuxDevice {
    id: String,
    name: String,
    file: Mutex<File>,
    size: u64,
    writable: bool,
    fs_type: Option<FsType>,
}

impl LinuxDevice {
    /// Open a block device by path (e.g., "/dev/sda1").
    ///
    /// Requires appropriate permissions (typically root).
    /// Opens read-only by default unless `writable` is true.
    pub fn open(path: &str, writable: bool) -> Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true);
        if writable {
            opts.write(true);
        }
        // O_NONBLOCK so open doesn't block on devices
        opts.custom_flags(libc::O_NONBLOCK);

        let file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Error::PermissionDenied
            } else {
                Error::IoGeneral(e)
            }
        })?;

        // Get device size via seek
        let size = {
            let mut f = file.try_clone().map_err(Error::IoGeneral)?;
            f.seek(SeekFrom::End(0)).map_err(Error::IoGeneral)?
        };

        Ok(Self {
            id: path.to_string(),
            name: path.split('/').next_back().unwrap_or(path).to_string(),
            file: Mutex::new(file),
            size,
            writable,
            fs_type: None,
        })
    }

    /// Open a regular file as a "device" (useful for disk images).
    pub fn open_image(path: &str) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(Error::IoGeneral)?;
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .map_err(Error::IoGeneral)?;

        Ok(Self {
            id: path.to_string(),
            name: path
                .rsplit('/')
                .next()
                .unwrap_or(path)
                .to_string(),
            file: Mutex::new(file),
            size: metadata.len(),
            writable: false,
            fs_type: None,
        })
    }
}

impl Device for LinuxDevice {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn fs_type(&self) -> Option<FsType> {
        self.fs_type
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let mut file = self.file.lock().map_err(|_| {
            Error::IoGeneral(std::io::Error::other(
                "mutex poisoned",
            ))
        })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io { offset, source: e })?;

        let n = file
            .read(buf)
            .map_err(|e| Error::Io { offset, source: e })?;

        Ok(n)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(Error::PermissionDenied);
        }

        use std::io::Write;

        let mut file = self.file.lock().map_err(|_| {
            Error::IoGeneral(std::io::Error::other(
                "mutex poisoned",
            ))
        })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io { offset, source: e })?;

        let n = file
            .write(buf)
            .map_err(|e| Error::Io { offset, source: e })?;

        Ok(n)
    }

    fn is_writable(&self) -> bool {
        self.writable
    }
}
