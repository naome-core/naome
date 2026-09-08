use std::{
    fs::File,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, Prefix},
};

use windows_permissions::{
    constants::{SeObjectType, SecurityInformation},
    wrappers,
};

use super::super::Result;

pub(super) fn regular(path: &Path) -> Result<File> {
    // Reject device namespaces and DOS aliases before opening: their open can
    // block or affect a device before descriptor metadata becomes available.
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::UNC(_, share) | Prefix::VerbatimUNC(_, share)
                    if share.to_str().is_some_and(|share| share.eq_ignore_ascii_case("pipe"))) =>
            {
                return Err("file_not_regular");
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
                return Err("file_not_regular");
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
                    return Err("file_not_regular");
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
        return Err("file_not_regular");
    }
    Ok(file)
}

pub(super) fn private(file: &File) -> Result<()> {
    // Use only these audited wrappers, never WindowsSecure (wrong object type)
    // or the DACL/ACE accessors (which panic on valid unsupported ACL forms).
    let descriptor = wrappers::GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| "seed_permissions")?;
    // Private executable, no impersonation, explicit System allocator in main.
    // Re-audit this wrapper if the allocator/toolchain/identity model changes.
    let process_sid =
        windows_permissions::utilities::current_process_sid().map_err(|_| "seed_permissions")?;
    if wrappers::GetSecurityDescriptorOwner(&descriptor).map_err(|_| "seed_permissions")?
        != Some(&*process_sid)
    {
        return Err("seed_permissions");
    }
    let dacl = wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )
    .map_err(|_| "seed_permissions")?;
    if !super::windows_acl::owner_only(
        dacl.to_str().ok_or("seed_permissions")?,
        &process_sid.to_string(),
    ) {
        return Err("seed_permissions");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        sync::atomic::{AtomicU64, Ordering},
    };
    use windows_permissions::{LocalBox, SecurityDescriptor};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture(path: &Path, private_acl: bool, byte: u8) {
        let owner = windows_permissions::utilities::current_process_sid().unwrap();
        let broad = if private_acl { "" } else { "(A;;FR;;;WD)" };
        let descriptor: LocalBox<SecurityDescriptor> =
            format!("O:{owner}D:P(A;;FA;;;{owner}){broad}")
                .parse()
                .unwrap();
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(0xc00c_0000) // GENERIC_READ/WRITE + WRITE_DAC/OWNER.
            .open(path)
            .unwrap();
        // The fixture constructs exactly the non-null ordinary ACL above.
        wrappers::SetSecurityInfo(
            &mut file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner
                | SecurityInformation::Dacl
                | SecurityInformation::ProtectedDacl,
            Some(&owner),
            None,
            descriptor.dacl(),
            None,
        )
        .unwrap();
        file.write_all(&[byte; 32]).unwrap();
    }

    #[test]
    fn opened_seed_owner_acl_and_bytes_do_not_follow_a_substituted_path() {
        for original_private in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "naome-seed-handle-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let path = root.join("seed");
            fixture(&path, original_private, 0x42);
            let mut opened = regular(&path).unwrap();
            fs::rename(&path, root.join("original")).unwrap();
            fixture(&path, !original_private, 0x93);
            assert_eq!(private(&opened).is_ok(), original_private);
            assert_eq!(super::super::seed(&path).is_ok(), !original_private);
            let mut bytes = Vec::new();
            opened.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, [0x42; 32]);
            drop(opened);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
