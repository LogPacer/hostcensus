//! The Windows Event Log API, called directly.
//!
//! This is the one file in hostcensus that contains `unsafe` code. Windows
//! offers no safe way to list the event-log channels and count their records:
//! the alternative is to start `wevtutil` once per channel, several hundred
//! times per census.
#![allow(unsafe_code)]

use std::fmt;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, GetLastError,
};
use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtClose, EvtGetLogInfo, EvtLogNumberOfLogRecords, EvtNextChannelPath,
    EvtOpenChannelEnum, EvtOpenChannelPath, EvtOpenLog, EvtVarTypeUInt64,
};

/// A call Windows refused, with its error code.
#[derive(Debug)]
pub(super) struct ApiError {
    call: &'static str,
    code: u32,
}

impl ApiError {
    fn last(call: &'static str) -> Self {
        // SAFETY: reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        Self { call, code }
    }

    pub(super) fn is_access_denied(&self) -> bool {
        self.code == ERROR_ACCESS_DENIED
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed: {}",
            self.call,
            std::io::Error::from_raw_os_error(self.code as i32)
        )
    }
}

/// Every channel registered on this host.
pub(super) fn channel_names() -> Result<Vec<String>, ApiError> {
    // SAFETY: session 0 is this host; no flags are defined.
    let channels = unsafe { EvtOpenChannelEnum(0, 0) };
    if channels == 0 {
        return Err(ApiError::last("EvtOpenChannelEnum"));
    }
    let channels = Handle(channels);

    let mut names = Vec::new();
    let mut buffer = vec![0u16; 256];
    loop {
        let mut used = 0u32;
        // SAFETY: `buffer` holds `len` UTF-16 units, and `used` is a valid
        // place for the count Windows writes.
        let ok = unsafe {
            EvtNextChannelPath(
                channels.0,
                buffer.len() as u32,
                buffer.as_mut_ptr(),
                &mut used,
            )
        };
        if ok != 0 {
            let length = (used as usize).min(buffer.len());
            names.push(
                String::from_utf16_lossy(&buffer[..length])
                    .trim_end_matches('\0')
                    .to_string(),
            );
            continue;
        }
        let error = ApiError::last("EvtNextChannelPath");
        match error.code {
            ERROR_NO_MORE_ITEMS => return Ok(names),
            ERROR_INSUFFICIENT_BUFFER => buffer.resize(used as usize, 0),
            _ => return Err(error),
        }
    }
}

/// How many records `channel` holds.
pub(super) fn record_count(channel: &str) -> Result<u64, ApiError> {
    let channel: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `channel` is NUL-terminated UTF-16 that outlives the call, and
    // session 0 is this host.
    let log = unsafe { EvtOpenLog(0, channel.as_ptr(), EvtOpenChannelPath) };
    if log == 0 {
        return Err(ApiError::last("EvtOpenLog"));
    }
    let log = Handle(log);

    let mut value = EVT_VARIANT::default();
    let mut used = 0u32;
    // SAFETY: `value` is one EVT_VARIANT, which is the size passed, and
    // `used` is a valid place for the size Windows writes.
    let ok = unsafe {
        EvtGetLogInfo(
            log.0,
            EvtLogNumberOfLogRecords,
            std::mem::size_of::<EVT_VARIANT>() as u32,
            &mut value,
            &mut used,
        )
    };
    if ok == 0 {
        return Err(ApiError::last("EvtGetLogInfo"));
    }
    // A channel that was never written to reports a null value.
    Ok(if value.Type == EvtVarTypeUInt64 as u32 {
        // SAFETY: the type tag says the union holds a u64.
        unsafe { value.Anonymous.UInt64Val }
    } else {
        0
    })
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from the Event Log API and is closed once.
        unsafe {
            EvtClose(self.0);
        }
    }
}
