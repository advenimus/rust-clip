//! Library surface of the RustClip desktop client.
//!
//! Both the CLI bin (`rustclip-client`) and the Tauri GUI bin
//! (`rustclip-client-gui`) consume this crate. The CLI layer lives in
//! `main.rs` and handles argument parsing + stdout rendering; the GUI
//! calls the same modules directly and wraps their results with Tauri
//! commands.

pub mod clipboard;
pub mod clipboard_files;
pub mod commands;
pub mod crypto;
pub mod files;
pub mod gui_api;
pub mod history;
pub mod http;
pub mod image_codec;
pub mod keychain;
pub mod sync;
