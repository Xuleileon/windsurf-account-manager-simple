# Local credential storage fork

Changes from upstream 1.8.1:

- Encrypt SQLite password, session token, refresh token, Windsurf API key and Devin auth1 token with AES-256-GCM. The master key stays in the operating system credential store.
- Migrate legacy SQLite credentials transactionally on startup, then checkpoint and vacuum the database. Invalid encrypted records fail explicitly; they are not silently dropped. A missing key is never replaced when encrypted records exist.
- Devin dates are local refresh scheduling hints, not server-guaranteed expiry dates.
- Disable automatic updates by default until this fork has its own signing key and release feed. Do not enable VITE_SIGNED_UPDATES until both are configured. Windows builds default to normal user privileges; REQUIRE_ADMIN=true remains available for deployments that need privileged operations.

## Backup and export

An encrypted database backup alone is not portable: it needs the original OS credential store key. Losing that key means signing in again or restoring a separately protected export. Explicit account exports remain plaintext for compatibility and must be stored securely. Existing JSON files, old backups, logs, and external client credentials are not retroactively encrypted by this change. No accounts are imported or logged in automatically.

## Scope

This change does not add account rotation, token refresh scheduling, or a Fast Context credential API. It does not extend a server-issued credential lifetime. Existing manual login/refresh flows remain in place.

## Verification

Run `npm run build`, `cargo test --manifest-path src-tauri/Cargo.toml --lib`, and `npm run tauri -- build --bundles nsis` on Windows. Credential tests use isolated in-memory databases and generated test keys, never real account credentials.

Validation on 2026-09-15: frontend production build and all three credential storage regression tests passed. The full library suite has two failures in unchanged upstream tests (`services::proto_parser::tests::test_parse_protobuf` and `utils::card_generator::tests::test_generate_card_number`); it is not reported as fully passing. Account login and refresh with real credentials have not been exercised by this patch.
