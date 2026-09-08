//! Native file-metadata synchronization is supported only on local NTFS.

use std::{fs, io, path::Path};

pub(super) fn require_local_ntfs(directory: &Path) -> io::Result<()> {
    // Directory routing remains caller-owned, as on Unix. Resolve junctions
    // before querying the volume so a mount below a drive root is not mistaken
    // for that drive's filesystem.
    let resolved = fs::canonicalize(directory)?;
    let path = resolved
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "storage path is not Unicode"))?;
    let volume = winsafe::GetVolumePathName(path).map_err(native_error)?;
    let drive = winsafe::GetDriveType(Some(&volume));
    if drive != winsafe::co::DRIVE::FIXED && drive != winsafe::co::DRIVE::REMOVABLE {
        return Err(unsupported());
    }
    let mut filesystem = String::new();
    winsafe::GetVolumeInformation(Some(&volume), None, None, None, None, Some(&mut filesystem))
        .map_err(native_error)?;
    if filesystem != "NTFS" {
        return Err(unsupported());
    }
    Ok(())
}

fn native_error(error: winsafe::co::ERROR) -> io::Error {
    io::Error::from_raw_os_error(error.raw() as i32)
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows finality storage requires local NTFS",
    )
}
