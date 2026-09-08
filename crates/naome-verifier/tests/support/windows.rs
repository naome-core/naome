use std::{path::Path, process::Command, thread, time::Instant};

use super::{BOUND, StopSignal};

pub fn seed_acl(path: &Path, mode: &str) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/windows_seed_acl.ps1");
    let mut helper = Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(script)
        .arg(path)
        .arg(mode)
        .spawn()
        .unwrap();
    wait_helper(&mut helper).expect("Windows ACL fixture helper");
}

pub(super) fn signal(process_id: u32, signal: StopSignal) -> Result<(), String> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/windows_signal.ps1");
    let mut helper = Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(script)
        .arg(process_id.to_string())
        .arg(match signal {
            StopSignal::Interrupt => "0",
            StopSignal::Terminate => "1",
        })
        .spawn()
        .unwrap();
    wait_helper(&mut helper)
}

fn wait_helper(helper: &mut std::process::Child) -> Result<(), String> {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(status) = helper.try_wait().unwrap() {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("Windows fixture helper failed: {status}"))
            };
        }
        if Instant::now() >= deadline {
            let _ = helper.kill();
            let _ = helper.wait();
            return Err("Windows fixture helper timed out".to_owned());
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
}
