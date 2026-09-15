// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--fast-context-credential") {
        std::process::exit(windsurf_account_manager_lib::fast_context::credential_cli());
    }
    windsurf_account_manager_lib::run()
}
