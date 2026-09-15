//! Local credential bridge. No listener or plaintext credential export.
use crate::{models::{Account, AccountStatus}, repository::{DataStore, SqliteAccountStore}};
use std::{path::PathBuf, sync::Arc};
use tauri::State;

fn ready(a: &Account) -> bool {
    matches!(a.status, AccountStatus::Active) && a.is_disabled != Some(true)
        && a.windsurf_api_key.as_deref().is_some_and(|k| !k.trim().is_empty())
}

#[tauri::command]
pub fn fast_context_accounts(store: State<'_, Arc<DataStore>>) -> Result<serde_json::Value, String> {
    let accounts = store.account_store.get_all_accounts().map_err(|_| "Cannot read accounts")?;
    Ok(serde_json::json!({"accounts": accounts.iter().map(|a|
        serde_json::json!({"id": a.id, "label": if a.nickname.is_empty() { &a.email } else { &a.nickname }, "ready": ready(a)})
    ).collect::<Vec<_>>()}))
}

fn credentials(accounts: Vec<Account>) -> serde_json::Value {
    serde_json::json!({"accounts": accounts.into_iter().filter(ready).map(|a|
        serde_json::json!({"accountId": a.id, "apiKey": a.windsurf_api_key.unwrap()})
    ).collect::<Vec<_>>()})
}

/// Runs before GUI startup. Stdout is a private pipe to the MCP process.
pub fn credential_cli() -> i32 {
    let result = (|| {
        let base = std::env::var_os("APPDATA").ok_or("WAM_DATA_NOT_FOUND")?;
        let db = PathBuf::from(base).join("com.chao.windsurf-account-manager").join("accounts.db");
        if !db.is_file() { return Err("WAM_DATA_NOT_FOUND"); }
        let store = SqliteAccountStore::open(&db).map_err(|_| "WAM_STORAGE_ERROR")?;
        let accounts = store.get_all_accounts().map_err(|_| "WAM_STORAGE_ERROR")?;
        Ok(credentials(accounts))
    })();
    match result {
        Ok(value) => { println!("{}", value); 0 }
        Err(code) => { println!("{}", serde_json::json!({"error": code})); 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_filters_accounts_and_never_exports_login_secrets() {
        let mut a = Account::new("test@example.invalid".into(), "private-password".into(), "test".into(), vec![]);
        a.windsurf_api_key = Some("fake-api-key".into());
        a.status = AccountStatus::Active;
        a.refresh_token = Some("private-refresh".into());
        let mut disabled = a.clone(); disabled.is_disabled = Some(true);
        let mut missing = a.clone(); missing.windsurf_api_key = None;
        let value = credentials(vec![a, disabled, missing]);
        assert_eq!(value["accounts"].as_array().unwrap().len(), 1);
        assert!(!value.to_string().contains("private-"));
        assert_eq!(value["accounts"][0]["apiKey"], "fake-api-key");
    }
}
