//! Native OS clipboard access for file lists.
//!
//! Two directions:
//!   - `write_file_list` — after the client receives a file bundle and
//!     unpacks it, this puts the unpacked paths on the OS pasteboard so
//!     the user can paste them into their file manager.
//!   - `read_file_list`  — the watcher side: if the user right-clicks in
//!     Finder / Explorer and chooses "Copy", this returns the file list so
//!     the sync loop can tar + encrypt + send.
//!
//! Platform support:
//!   - macOS : full (objc2 / NSPasteboard / NSURL).
//!   - Windows: full (windows crate / CF_HDROP / DragQueryFileW).
//!   - Linux : stubbed. arboard has no file-list reader, and the
//!     GNOME/KDE/X11/Wayland surface varies too much to ship here; the
//!     `send-files` CLI remains the Linux path.

use std::path::PathBuf;

use anyhow::Result;

pub fn write_file_list(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    platform::write_file_list(paths)
}

/// Read any file paths currently on the OS clipboard. Returns
/// `Ok(None)` when the clipboard contains no file URLs (the common
/// case), `Ok(Some(paths))` when the user has copied files, and `Err`
/// only for unexpected failures (e.g. objc2 downcast failed).
pub fn read_file_list() -> Result<Option<Vec<PathBuf>>> {
    platform::read_file_list()
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::PathBuf;

    use anyhow::{Result, anyhow};
    use objc2::{
        ClassType,
        rc::Retained,
        runtime::{AnyClass, ProtocolObject},
    };
    use objc2_app_kit::{NSPasteboard, NSPasteboardWriting};
    use objc2_foundation::{NSArray, NSString, NSURL};

    pub fn write_file_list(paths: &[PathBuf]) -> Result<()> {
        let pb = NSPasteboard::generalPasteboard();
        pb.clearContents();
        let mut writers: Vec<Retained<ProtocolObject<dyn NSPasteboardWriting>>> =
            Vec::with_capacity(paths.len());
        for p in paths {
            let s = p
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 path: {}", p.display()))?;
            let ns_path = NSString::from_str(s);
            let url = NSURL::fileURLWithPath(&ns_path);
            let writer: Retained<ProtocolObject<dyn NSPasteboardWriting>> =
                ProtocolObject::from_retained(url);
            writers.push(writer);
        }
        let array: Retained<NSArray<ProtocolObject<dyn NSPasteboardWriting>>> =
            NSArray::from_retained_slice(&writers);
        let ok = pb.writeObjects(&array);
        if !ok {
            return Err(anyhow!("NSPasteboard rejected the file URL list"));
        }
        Ok(())
    }

    pub fn read_file_list() -> Result<Option<Vec<PathBuf>>> {
        unsafe {
            let pb = NSPasteboard::generalPasteboard();
            let nsurl_cls: &AnyClass = <NSURL as ClassType>::class();
            let classes: Retained<NSArray<AnyClass>> = NSArray::from_slice(&[nsurl_cls]);
            let Some(objs) = pb.readObjectsForClasses_options(&classes, None) else {
                return Ok(None);
            };
            if objs.count() == 0 {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(objs.count());
            for obj in objs.iter() {
                let url: &NSURL = obj
                    .downcast_ref::<NSURL>()
                    .ok_or_else(|| anyhow!("pasteboard object is not NSURL"))?;
                let Some(ns_path) = url.path() else {
                    continue;
                };
                out.push(PathBuf::from(ns_path.to_string()));
            }
            if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(out))
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::{
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::PathBuf,
    };

    use anyhow::{Result, anyhow};
    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            DataExchange::{
                CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
                OpenClipboard, SetClipboardData,
            },
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        },
        UI::Shell::{DragQueryFileW, HDROP},
    };

    // CF_HDROP = 15. Hard-coded to avoid pulling the Win32_System_Ole
    // feature of the `windows` crate for a single integer constant.
    const CF_HDROP: u32 = 15;

    struct ClipboardGuard;
    impl ClipboardGuard {
        fn open() -> Result<Self> {
            unsafe { OpenClipboard(None) }.map_err(|e| anyhow!("OpenClipboard: {e}"))?;
            Ok(Self)
        }
    }
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    pub fn write_file_list(paths: &[PathBuf]) -> Result<()> {
        // Build a DROPFILES payload: a DROPFILES struct followed by a
        // double-null-terminated UTF-16 list of paths.
        let mut wide: Vec<u16> = Vec::new();
        for p in paths {
            let s: Vec<u16> = p
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0u16))
                .collect();
            wide.extend(s);
        }
        wide.push(0); // terminating null for the double-null list

        const DROPFILES_SIZE: usize = 20; // sizeof(DROPFILES) on x64 and x86
        let payload_bytes = DROPFILES_SIZE + wide.len() * 2;
        let _guard = ClipboardGuard::open()?;
        unsafe {
            EmptyClipboard().map_err(|e| anyhow!("EmptyClipboard: {e}"))?;
            let h = GlobalAlloc(GMEM_MOVEABLE, payload_bytes)
                .map_err(|e| anyhow!("GlobalAlloc: {e}"))?;
            let ptr = GlobalLock(h);
            if ptr.is_null() {
                return Err(anyhow!("GlobalLock returned null"));
            }
            std::ptr::write_bytes(ptr as *mut u8, 0, DROPFILES_SIZE);
            // DROPFILES.pFiles = sizeof(DROPFILES) (files follow immediately)
            *(ptr as *mut u32) = DROPFILES_SIZE as u32;
            // DROPFILES.fWide = TRUE at offset 16. We write -1 (all bits set)
            // instead of 1 to match .NET's Clipboard.SetFileDropList, which is
            // what every other Windows app emits. Some shell reader code paths
            // check fWide == TRUE with TRUE==-1 and fall through to the ANSI
            // parser otherwise, producing a silently-empty FileDropList.
            *((ptr as *mut u8).add(16) as *mut i32) = -1;
            let dst = (ptr as *mut u8).add(DROPFILES_SIZE) as *mut u16;
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
            let _ = GlobalUnlock(h);
            SetClipboardData(CF_HDROP, HANDLE(h.0 as *mut _))
                .map_err(|e| anyhow!("SetClipboardData: {e}"))?;
        }
        Ok(())
    }

    pub fn read_file_list() -> Result<Option<Vec<PathBuf>>> {
        unsafe {
            if IsClipboardFormatAvailable(CF_HDROP).is_err() {
                return Ok(None);
            }
        }
        let _guard = ClipboardGuard::open()?;
        unsafe {
            let h = match GetClipboardData(CF_HDROP) {
                Ok(h) => h,
                Err(_) => return Ok(None),
            };
            let hdrop = HDROP(h.0 as *mut _);
            let count = DragQueryFileW(hdrop, 0xFFFFFFFF, None);
            if count == 0 {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                let needed = DragQueryFileW(hdrop, i, None) as usize;
                if needed == 0 {
                    continue;
                }
                let mut buf = vec![0u16; needed + 1];
                let copied = DragQueryFileW(hdrop, i, Some(buf.as_mut_slice()));
                buf.truncate(copied as usize);
                let os = std::ffi::OsString::from_wide(&buf);
                out.push(PathBuf::from(os));
            }
            if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(out))
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod platform {
    use std::path::PathBuf;

    use anyhow::Result;

    // Linux (X11 + Wayland, multiple desktop environments with different
    // pasteboard formats) is deferred — the `send-files` CLI still works.
    pub fn write_file_list(_paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }

    pub fn read_file_list() -> Result<Option<Vec<PathBuf>>> {
        Ok(None)
    }
}
