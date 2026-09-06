#![cfg(unix)]

mod support;

#[path = "cases/lifecycle.rs"]
mod lifecycle;
#[path = "cases/rejections.rs"]
mod rejections;
#[path = "cases/restart.rs"]
mod restart;
