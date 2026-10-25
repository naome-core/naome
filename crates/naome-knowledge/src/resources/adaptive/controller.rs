//! The native node publishes live budgets without persisting observation history.
use super::*;
use std::path::PathBuf;

pub(crate) struct Controller {
    directory: PathBuf,
    observer: Observer,
}

impl Controller {
    pub(crate) fn open(directory: &Path) -> Result<Self, String> {
        let mut owner = Self {
            directory: directory.to_owned(),
            observer: Observer::default(),
        };
        owner.refresh()?;
        Ok(owner)
    }

    pub(crate) fn refresh(&mut self) -> Result<(), String> {
        let Some(snapshot) = self
            .observer
            .poll(&self.directory)
            .map_err(|error| error.to_string())?
            .cloned()
        else {
            return Ok(());
        };
        // Native process regressions observe the same owner through the existing
        // bounded log. Ordinary product builds expose no resource diagnostic API.
        #[cfg(feature = "developer-tools")]
        if std::env::var_os("NAOME_DEV_RESOURCE_OBSERVATIONS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            crate::network::emit(serde_json::json!({
                "event": "resource_observation",
                "snapshot": &snapshot,
                "capacity_bytes": super::super::limits().memory_bytes,
                "feedback": super::super::feedback::statistics(),
            }));
        }
        publish(snapshot);
        Ok(())
    }
}
