#![cfg(unix)]

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
