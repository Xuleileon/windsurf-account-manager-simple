//! One persistent directory selection for the GUI and the credential bridge.
use std::path::PathBuf;
use tauri::Manager;

#[cfg(windows)]
fn configured_directory() -> Result<Option<String>, String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\WindsurfAccountManager") {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot read WAM data directory setting".into()),
    };
    match key.get_value("DataDirectory") {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("Invalid WAM data directory setting".into()),
    }
}

#[cfg(not(windows))]
fn configured_directory() -> Result<Option<String>, String> { Ok(None) }

fn resolve(configured: Option<String>, default: impl FnOnce() -> Result<PathBuf, String>) -> Result<PathBuf, String> {
    match configured {
        None => default(),
        Some(value) => {
            let path = PathBuf::from(value);
            // A configured location must already be migrated. Never create an empty
            // replacement account store or silently return to a different profile.
            if !path.is_absolute() || !path.join("accounts.db").is_file() {
                return Err("Configured WAM data directory must be absolute and contain accounts.db; restore its access or the original setting".into());
            }
            Ok(path)
        }
    }
}

pub fn for_app(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    resolve(configured_directory()?, || app.path().app_data_dir().map_err(|e| e.to_string()))
}

pub fn for_bridge() -> Result<PathBuf, String> {
    resolve(configured_directory()?, || {
        std::env::var_os("APPDATA")
            .map(|base| PathBuf::from(base).join("com.chao.windsurf-account-manager"))
            .ok_or_else(|| "WAM data directory is unavailable".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_store_is_shared_without_consulting_profile() {
        let dir = std::env::temp_dir().join(format!("wam-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("accounts.db"), b"fixture").unwrap();
        let result = resolve(Some(dir.to_string_lossy().into()), || panic!("must not use profile"));
        assert_eq!(result.unwrap(), dir);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn invalid_configured_store_never_falls_back_or_creates_data() {
        for value in ["relative".to_string(), std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()).to_string_lossy().into()] {
            assert!(resolve(Some(value), || panic!("must not fall back")).is_err());
        }
    }
    #[test]
    fn unconfigured_install_preserves_default() {
        assert_eq!(resolve(None, || Ok(PathBuf::from("default"))).unwrap(), PathBuf::from("default"));
    }
}
