//! Public archive input protection, retained from the verifier's regular-file reader.
use super::Result;
use std::{
    fs::File,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, Prefix},
};

pub(super) fn regular(path: &Path) -> Result<File> {
    // Reject device namespaces and DOS aliases before opening: their open can
    // block or affect a device before descriptor metadata becomes available.
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::UNC(_, share) | Prefix::VerbatimUNC(_, share)
                    if share.to_str().is_some_and(|share| share.eq_ignore_ascii_case("pipe"))) =>
            {
                return Err("file_not_regular".into());
            }
            Component::Prefix(prefix)
                if !matches!(
                    prefix.kind(),
                    Prefix::Disk(_)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::UNC(_, _)
                        | Prefix::VerbatimUNC(_, _)
                ) =>
            {
                return Err("file_not_regular".into());
            }
            Component::Normal(name) => {
                let name = name.to_str().ok_or("file_not_regular")?;
                let stem = name
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(' ')
                    .to_ascii_uppercase();
                if name.contains(':')
                    || matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    )
                    || ["COM", "LPT"].iter().any(|prefix| {
                        stem.strip_prefix(prefix).is_some_and(|suffix| {
                            matches!(
                                suffix,
                                "1" | "2"
                                    | "3"
                                    | "4"
                                    | "5"
                                    | "6"
                                    | "7"
                                    | "8"
                                    | "9"
                                    | "¹"
                                    | "²"
                                    | "³"
                            )
                        })
                    })
                {
                    return Err("file_not_regular".into());
                }
            }
            _ => {}
        }
    }
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const REPARSE_DIRECTORY_OR_DEVICE: u32 = 0x400 | 0x10 | 0x40;
    let file = File::options()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|_| "file_open")?;
    let metadata = file.metadata().map_err(|_| "file_metadata")?;
    if !metadata.is_file() || metadata.file_attributes() & REPARSE_DIRECTORY_OR_DEVICE != 0 {
        return Err("file_not_regular".into());
    }
    Ok(file)
}
