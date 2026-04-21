//! Native OS clipboard access for file lists.
//!
//! After a file bundle is received and unpacked into the inbox, we place
//! the unpacked file paths on the OS pasteboard so the user can paste them
//! into Finder / Explorer / their file manager. v1 writes only; reading
//! file lists off the clipboard (to mirror a Cmd+C in Finder) is deferred
//! to Phase 6 polish because it needs active polling across three
//! different native backends.

use std::path::PathBuf;

use anyhow::Result;

pub fn write_file_list(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    platform::write_file_list(paths)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::PathBuf;

    use anyhow::{Result, anyhow};
    use objc2::{rc::Retained, runtime::ProtocolObject};
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
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::path::PathBuf;

    use anyhow::Result;

    pub fn write_file_list(_paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }
}
