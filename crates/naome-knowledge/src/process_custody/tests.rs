use super::*;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use std::os::{fd::OwnedFd, unix::net::UnixStream};

#[test]
fn failed_spawn_preserves_the_parent_descriptor_flags() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let slot = File::from(OwnedFd::from(socket));
    for original in [FdFlag::FD_CLOEXEC, FdFlag::empty()] {
        fcntl(&slot, FcntlArg::F_SETFD(original)).unwrap();
        let (child, restoration) = spawn_with_slot(&slot, || {
            let inherited = FdFlag::from_bits_retain(fcntl(&slot, FcntlArg::F_GETFD).unwrap());
            assert!(!inherited.contains(FdFlag::FD_CLOEXEC));
            std::process::Command::new("/naome/nonexistent-process-fixture").spawn()
        })
        .unwrap();
        assert!(child.is_err());
        restoration.unwrap();
        assert_eq!(fcntl(&slot, FcntlArg::F_GETFD).unwrap(), original.bits());
    }
}
