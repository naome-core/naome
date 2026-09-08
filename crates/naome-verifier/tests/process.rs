#![cfg(any(unix, windows))]

mod support;

#[path = "cases/archive.rs"]
mod archive;
#[path = "cases/archive_peer.rs"]
mod archive_peer;
#[path = "cases/lifecycle.rs"]
mod lifecycle;
#[path = "cases/rejections.rs"]
mod rejections;
#[path = "cases/restart.rs"]
mod restart;
#[path = "cases/validator_provider.rs"]
#[cfg(unix)]
mod validator_provider;

#[path = "cases/windows.rs"]
#[cfg(windows)]
mod windows;
