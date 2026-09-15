//! SQLite 账号存储层（v1.7.8 方案 B：10 万+ 账户性能重构）
//!
//! 替代原 `DataStore` 中基于 `AppConfig.accounts: Vec<Account>` + JSON 全量落盘的实现。
//! 每个写操作仅涉及单行 INSERT/UPDATE/DELETE（~1KB IO），10 万级账户下查询响应 <10ms。
//!
//! # 线程安全
//!
//! `rusqlite::Connection` 不是 `Send`。本模块持有 `std::sync::Mutex<Connection>`，
//! 所有操作在 `tokio::task::spawn_blocking` 中执行（或直接 inline lock，因 SQLite
//! 单次操作 <10ms，不会阻塞 tokio runtime）。

use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::crypto::CryptoService;
use crate::models::{Account, AccountStatus, TagWithColor};
use crate::utils::{AppError, AppResult};

/// 分页查询请求（前端传入，tauri command 反序列化）
#[derive(Debug, Default, Deserialize)]
pub struct AccountPageRequest {
    /// 1-indexed 页码
    #[serde(default = "default_page")]
    pub page: u32,
    /// 每页条数，默认 20
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// 模糊搜索（email / nickname / tags）
    pub search: Option<String>,
    /// 按分组精确筛选
    pub group: Option<String>,
    /// 按标签筛选（任一匹配）
    pub tags: Option<Vec<String>>,
    /// 按套餐名筛选
    pub plan_names: Option<Vec<String>>,
    /// 按域名筛选
    pub domains: Option<Vec<String>>,
    /// 按状态筛选（normal/offline/error/disabled/inactive）
    pub statuses: Option<Vec<String>>,
    /// 剩余额度范围（已乘 100）
    pub remaining_quota_min: Option<i32>,
    pub remaining_quota_max: Option<i32>,
    /// 总额度范围（已乘 100）
    pub total_quota_min: Option<i32>,
    pub total_quota_max: Option<i32>,
    /// 剩余天数范围
    pub expiry_days_min: Option<i32>,
    pub expiry_days_max: Option<i32>,
    /// 日/周配额百分比范围
    pub daily_quota_percent_min: Option<i32>,
    pub daily_quota_percent_max: Option<i32>,
    pub weekly_quota_percent_min: Option<i32>,
    pub weekly_quota_percent_max: Option<i32>,
    /// 排序字段
    pub sort_field: Option<String>,
    /// 排序方向 asc / desc
    pub sort_direction: Option<String>,
}

fn default_page() -> u32 { 1 }
fn default_page_size() -> u32 { 20 }

/// 分页查询响应
#[derive(Debug, Serialize)]
pub struct AccountPageResponse {
    pub accounts: Vec<Account>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

/// 聚合统计（供前端下拉框 / 统计面板使用）
#[derive(Debug, Serialize)]
pub struct AccountAggregates {
    pub total_count: u64,
    pub groups: Vec<String>,
    pub plan_names: Vec<String>,
    pub domains: Vec<String>,
    pub tags: Vec<String>,
    pub active_count: u64,
    /// 每个分组的账号数量（供侧边栏分组列表显示）
    pub group_counts: std::collections::HashMap<String, u64>,
    /// 每个标签的使用次数（供标签管理页面显示）
    pub tag_counts: std::collections::HashMap<String, u64>,
}

pub struct SqliteAccountStore {
    conn: Mutex<Connection>,
    crypto: CryptoService,
    /// P2: COUNT(*) 结果缓存。key 为 filter 条件的 hash（不含 page/page_size/sort），
    /// value 为 `(count, 写入时刻)`。命中且未过期则跳过 SQL `COUNT(*)`，节省 20-100ms。
    /// 写操作（insert/upsert/delete/batch update）会清空缓存以保证一致性。
    count_cache: Mutex<HashMap<u64, (i64, Instant)>>,
}

impl SqliteAccountStore {
    /// 状态类型 SQL CASE 表达式，精确镜像前端 `getAccountStatusType` 的优先级链。
    ///
    /// 优先级（与前端一致）：
    /// 1. **error**：status 包含 "error"（覆盖 `"error"` 字符串 和 `{"error":"..."}` 对象两种 JSON 形式）
    /// 2. **inactive**：付费计划（plan_name 非空且非 free）且 subscription_active=0
    /// 3. **disabled**：is_disabled=1
    /// 4. **offline**：token 未设置或已过期
    /// 5. **normal**：其他情况
    const STATUS_CASE_EXPR: &'static str = r#"CASE
        WHEN status LIKE '%error%' THEN 'error'
        WHEN plan_name IS NOT NULL AND plan_name != '' AND LOWER(plan_name) != 'free' AND subscription_active = 0 THEN 'inactive'
        WHEN is_disabled = 1 THEN 'disabled'
        WHEN token_expires_at IS NULL OR token_expires_at < strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now') THEN 'offline'
        ELSE 'normal'
    END"#;
}

impl SqliteAccountStore {
    /// 打开（或创建）账号数据库，自动建表 + 索引。
    pub fn open(db_path: &PathBuf) -> AppResult<Self> {
        let conn = Connection::open(db_path)
            .map_err(|e| AppError::Config(format!("SQLite open failed: {}", e)))?;

        // WAL 模式：并发读 + 写不阻塞读
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")
            .map_err(|e| AppError::Config(format!("SQLite PRAGMA failed: {}", e)))?;

        conn.execute_batch(Self::CREATE_SCHEMA)
            .map_err(|e| AppError::Config(format!("SQLite schema failed: {}", e)))?;

        // 增量迁移：为已有数据库添加新字段
        Self::migrate_columns(&conn);

        let has_encrypted: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE password LIKE 'wam:v1:%' OR token LIKE 'wam:v1:%' OR refresh_token LIKE 'wam:v1:%' OR windsurf_api_key LIKE 'wam:v1:%' OR devin_auth1_token LIKE 'wam:v1:%')", [], |r| r.get(0))
            .map_err(|_| AppError::Config("Cannot inspect credential encryption state".into()))?;
        let crypto = CryptoService::open(!has_encrypted)
            .map_err(|e| AppError::Config(e.to_string()))?;
        let store = Self { conn: Mutex::new(conn), crypto, count_cache: Mutex::new(HashMap::new()) };
        store.migrate_credentials()?;
        Ok(store)
    }


    fn seal(&self, value: &str) -> AppResult<String> {
        if value.is_empty() { return Ok(String::new()); }
        self.crypto.encrypt(value).map(|v| format!("wam:v1:{}", v))
            .map_err(|_| AppError::Config("Credential encryption failed".into()))
    }

    fn unseal(&self, value: String) -> rusqlite::Result<String> {
        match value.strip_prefix("wam:v1:") {
            Some(ciphertext) => self.crypto.decrypt(ciphertext).map_err(|_| rusqlite::Error::InvalidQuery),
            None => Ok(value), // Legacy plaintext is migrated transactionally at open.
        }
    }

    fn seal_account(&self, account: &Account) -> AppResult<Account> {
        let mut stored = account.clone();
        stored.password = self.seal(&stored.password)?;
        stored.token = stored.token.as_deref().map(|v| self.seal(v)).transpose()?;
        stored.refresh_token = stored.refresh_token.as_deref().map(|v| self.seal(v)).transpose()?;
        stored.windsurf_api_key = stored.windsurf_api_key.as_deref().map(|v| self.seal(v)).transpose()?;
        stored.devin_auth1_token = stored.devin_auth1_token.as_deref().map(|v| self.seal(v)).transpose()?;
        Ok(stored)
    }

    fn migrate_credentials(&self) -> AppResult<()> {
        let mut conn = self.conn.lock().map_err(|_| AppError::Config("Store locked".into()))?;
        let tx = conn.transaction().map_err(|_| AppError::Config("Migration could not start".into()))?;
        let mut changed = false;
        for column in ["password", "token", "refresh_token", "windsurf_api_key", "devin_auth1_token"] {
            let sql = format!("SELECT id, {} FROM accounts WHERE {} IS NOT NULL AND {} != ''", column, column, column);
            let entries = {
                let mut stmt = tx.prepare(&sql).map_err(|_| AppError::Config("Migration query failed".into()))?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                    .map_err(|_| AppError::Config("Migration query failed".into()))?;
                rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|_| AppError::Config("Migration read failed".into()))?
            };
            for (id, value) in entries {
                if value.starts_with("wam:v1:") {
                    self.unseal(value).map_err(|_| AppError::Config("Credential decryption failed; migration rolled back".into()))?;
                    continue;
                }
                tx.execute(&format!("UPDATE accounts SET {}=?1 WHERE id=?2", column), params![self.seal(&value)?, id])
                    .map_err(|_| AppError::Config("Credential migration failed".into()))?;
                changed = true;
            }
        }
        tx.commit().map_err(|_| AppError::Config("Migration commit failed".into()))?;
        if changed {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|_| AppError::Config("Encrypted credentials saved, but database cleanup failed".into()))?;
        }
        Ok(())
    }

    fn migrate_columns(conn: &Connection) {
        let migrations = [
            "ALTER TABLE accounts ADD COLUMN parent_account_id TEXT",
            "ALTER TABLE accounts ADD COLUMN devin_org_id TEXT",
            "ALTER TABLE accounts ADD COLUMN devin_org_name TEXT",
        ];
        for sql in &migrations {
            let _ = conn.execute(sql, []);
        }
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_accounts_parent_account_id ON accounts(parent_account_id)",
            [],
        );
    }

    // ==================== P2: COUNT(*) 缓存 ====================

    /// COUNT 缓存 TTL：60 秒。写操作会强制 invalidate，TTL 主要防御长时间无写操作的极端场景。
    const COUNT_CACHE_TTL: Duration = Duration::from_secs(60);

    /// 计算 filter 条件的 hash key（仅 WHERE 相关字段，不含 page/page_size/sort）。
    fn hash_filter(req: &AccountPageRequest) -> u64 {
        let mut h = DefaultHasher::new();
        req.search.hash(&mut h);
        req.group.hash(&mut h);
        req.tags.hash(&mut h);
        req.plan_names.hash(&mut h);
        req.domains.hash(&mut h);
        req.statuses.hash(&mut h);
        req.remaining_quota_min.hash(&mut h);
        req.remaining_quota_max.hash(&mut h);
        req.total_quota_min.hash(&mut h);
        req.total_quota_max.hash(&mut h);
        req.expiry_days_min.hash(&mut h);
        req.expiry_days_max.hash(&mut h);
        req.daily_quota_percent_min.hash(&mut h);
        req.daily_quota_percent_max.hash(&mut h);
        req.weekly_quota_percent_min.hash(&mut h);
        req.weekly_quota_percent_max.hash(&mut h);
        h.finish()
    }

    /// 读 COUNT 缓存。命中且未过期返回 Some(count)，否则 None。
    fn get_cached_count(&self, key: u64) -> Option<i64> {
        let cache = self.count_cache.lock().ok()?;
        cache.get(&key).and_then(|(c, t)| {
            if t.elapsed() < Self::COUNT_CACHE_TTL { Some(*c) } else { None }
        })
    }

    /// 写 COUNT 缓存。
    fn set_cached_count(&self, key: u64, count: i64) {
        if let Ok(mut cache) = self.count_cache.lock() {
            cache.insert(key, (count, Instant::now()));
        }
    }

    /// 清空 COUNT 缓存。**所有改变 accounts 表行数或 filter 命中结果**的写操作必须调用此方法。
    fn invalidate_count_cache(&self) {
        if let Ok(mut cache) = self.count_cache.lock() {
            cache.clear();
        }
    }

    const CREATE_SCHEMA: &'static str = r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            password TEXT NOT NULL DEFAULT '',
            nickname TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '[]',
            tag_colors TEXT NOT NULL DEFAULT '[]',
            "group" TEXT,
            token TEXT,
            refresh_token TEXT,
            token_expires_at TEXT,
            last_seat_count INTEGER,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            status TEXT NOT NULL DEFAULT '"inactive"',
            plan_name TEXT,
            used_quota INTEGER,
            total_quota INTEGER,
            last_quota_update TEXT,
            subscription_expires_at TEXT,
            subscription_active INTEGER,
            windsurf_api_key TEXT,
            is_disabled INTEGER,
            is_team_owner INTEGER,
            billing_strategy INTEGER,
            daily_quota_remaining_percent INTEGER,
            weekly_quota_remaining_percent INTEGER,
            daily_quota_reset_at_unix INTEGER,
            weekly_quota_reset_at_unix INTEGER,
            overage_balance_micros INTEGER,
            sort_order INTEGER NOT NULL DEFAULT 0,
            devin_auth1_token TEXT,
            devin_account_id TEXT,
            devin_primary_org_id TEXT,
            auth_provider TEXT,
            parent_account_id TEXT,
            devin_org_id TEXT,
            devin_org_name TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_accounts_group ON accounts("group");
        CREATE INDEX IF NOT EXISTS idx_accounts_plan_name ON accounts(plan_name);
        CREATE INDEX IF NOT EXISTS idx_accounts_created_at ON accounts(created_at);
        CREATE INDEX IF NOT EXISTS idx_accounts_sort_order ON accounts(sort_order);
        CREATE INDEX IF NOT EXISTS idx_accounts_auth_provider ON accounts(auth_provider);
        -- 翻页热点：默认 ORDER BY sort_order ASC, created_at ASC 的覆盖索引，
        -- 避免 file sort，单查询从 50-200ms 降到 < 5ms（10w 级）。
        CREATE INDEX IF NOT EXISTS idx_accounts_sort_order_created_at ON accounts(sort_order, created_at);
        -- 排序/过滤热点：sort_field 可选 subscription_expires_at / token_expires_at；
        -- 高级筛选用 expiry_days_min/max 比较 subscription_expires_at。
        CREATE INDEX IF NOT EXISTS idx_accounts_subscription_expires_at ON accounts(subscription_expires_at);
        CREATE INDEX IF NOT EXISTS idx_accounts_token_expires_at ON accounts(token_expires_at);
        -- 排序/过滤热点：sort_field 可选 used_quota / remaining_quota；
        -- filter 用 total_quota_min/max、remaining_quota_min/max。
        CREATE INDEX IF NOT EXISTS idx_accounts_total_quota ON accounts(total_quota);
        -- 排序/过滤热点：sort_field 可选 daily/weekly_quota_remaining；
        -- filter 用 daily_quota_percent_min/max、weekly_quota_percent_min/max。
        CREATE INDEX IF NOT EXISTS idx_accounts_daily_quota_remaining ON accounts(daily_quota_remaining_percent);
        CREATE INDEX IF NOT EXISTS idx_accounts_weekly_quota_remaining ON accounts(weekly_quota_remaining_percent);
    "#;

    // ==================== CRUD ====================

    pub fn insert_account(&self, account: &Account) -> AppResult<()> {
        let account = self.seal_account(account)?;
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        conn.execute(
            r#"INSERT INTO accounts (
                id, email, password, nickname, tags, tag_colors, "group",
                token, refresh_token, token_expires_at, last_seat_count,
                created_at, last_login_at, status, plan_name, used_quota, total_quota,
                last_quota_update, subscription_expires_at, subscription_active,
                windsurf_api_key, is_disabled, is_team_owner, billing_strategy,
                daily_quota_remaining_percent, weekly_quota_remaining_percent,
                daily_quota_reset_at_unix, weekly_quota_reset_at_unix,
                overage_balance_micros, sort_order,
                devin_auth1_token, devin_account_id, devin_primary_org_id, auth_provider,
                parent_account_id, devin_org_id, devin_org_name
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20,
                ?21, ?22, ?23, ?24,
                ?25, ?26,
                ?27, ?28,
                ?29, ?30,
                ?31, ?32, ?33, ?34,
                ?35, ?36, ?37
            )"#,
            params![
                account.id.to_string(),
                account.email,
                account.password,
                account.nickname,
                serde_json::to_string(&account.tags).unwrap_or_default(),
                serde_json::to_string(&account.tag_colors).unwrap_or_default(),
                account.group,
                account.token,
                account.refresh_token,
                account.token_expires_at.map(|t| t.to_rfc3339()),
                account.last_seat_count,
                account.created_at.to_rfc3339(),
                account.last_login_at.map(|t| t.to_rfc3339()),
                serde_json::to_string(&account.status).unwrap_or_default(),
                account.plan_name,
                account.used_quota,
                account.total_quota,
                account.last_quota_update.map(|t| t.to_rfc3339()),
                account.subscription_expires_at.map(|t| t.to_rfc3339()),
                account.subscription_active.map(|b| b as i32),
                account.windsurf_api_key,
                account.is_disabled.map(|b| b as i32),
                account.is_team_owner.map(|b| b as i32),
                account.billing_strategy,
                account.daily_quota_remaining_percent,
                account.weekly_quota_remaining_percent,
                account.daily_quota_reset_at_unix,
                account.weekly_quota_reset_at_unix,
                account.overage_balance_micros,
                account.sort_order,
                account.devin_auth1_token,
                account.devin_account_id,
                account.devin_primary_org_id,
                account.auth_provider,
                account.parent_account_id.map(|u| u.to_string()),
                account.devin_org_id,
                account.devin_org_name,
            ],
        ).map_err(|e| AppError::Config(format!("insert_account: {}", e)))?;
        self.invalidate_count_cache();  // P2: 总数变化，下次翻页重查 COUNT
        Ok(())
    }

    pub fn upsert_account(&self, account: &Account) -> AppResult<()> {
        let account = self.seal_account(account)?;
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        conn.execute(
            r#"INSERT OR REPLACE INTO accounts (
                id, email, password, nickname, tags, tag_colors, "group",
                token, refresh_token, token_expires_at, last_seat_count,
                created_at, last_login_at, status, plan_name, used_quota, total_quota,
                last_quota_update, subscription_expires_at, subscription_active,
                windsurf_api_key, is_disabled, is_team_owner, billing_strategy,
                daily_quota_remaining_percent, weekly_quota_remaining_percent,
                daily_quota_reset_at_unix, weekly_quota_reset_at_unix,
                overage_balance_micros, sort_order,
                devin_auth1_token, devin_account_id, devin_primary_org_id, auth_provider,
                parent_account_id, devin_org_id, devin_org_name
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20,
                ?21, ?22, ?23, ?24,
                ?25, ?26,
                ?27, ?28,
                ?29, ?30,
                ?31, ?32, ?33, ?34,
                ?35, ?36, ?37
            )"#,
            params![
                account.id.to_string(),
                account.email,
                account.password,
                account.nickname,
                serde_json::to_string(&account.tags).unwrap_or_default(),
                serde_json::to_string(&account.tag_colors).unwrap_or_default(),
                account.group,
                account.token,
                account.refresh_token,
                account.token_expires_at.map(|t| t.to_rfc3339()),
                account.last_seat_count,
                account.created_at.to_rfc3339(),
                account.last_login_at.map(|t| t.to_rfc3339()),
                serde_json::to_string(&account.status).unwrap_or_default(),
                account.plan_name,
                account.used_quota,
                account.total_quota,
                account.last_quota_update.map(|t| t.to_rfc3339()),
                account.subscription_expires_at.map(|t| t.to_rfc3339()),
                account.subscription_active.map(|b| b as i32),
                account.windsurf_api_key,
                account.is_disabled.map(|b| b as i32),
                account.is_team_owner.map(|b| b as i32),
                account.billing_strategy,
                account.daily_quota_remaining_percent,
                account.weekly_quota_remaining_percent,
                account.daily_quota_reset_at_unix,
                account.weekly_quota_reset_at_unix,
                account.overage_balance_micros,
                account.sort_order,
                account.devin_auth1_token,
                account.devin_account_id,
                account.devin_primary_org_id,
                account.auth_provider,
                account.parent_account_id.map(|u| u.to_string()),
                account.devin_org_id,
                account.devin_org_name,
            ],
        ).map_err(|e| AppError::Config(format!("upsert_account: {}", e)))?;
        self.invalidate_count_cache();  // P2: filter 命中可能变化（quota / plan / status 等字段）
        Ok(())
    }

    pub fn get_account(&self, id: &Uuid) -> AppResult<Account> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut stmt = conn.prepare("SELECT * FROM accounts WHERE id = ?1")
            .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
        stmt.query_row(params![id.to_string()], |row| self.row_to_account(row))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => AppError::AccountNotFound(id.to_string()),
                _ => AppError::Config("Account read or credential decryption failed".into()),
            })
    }

    pub fn get_account_by_email(&self, email: &str) -> AppResult<Option<Account>> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut stmt = conn.prepare("SELECT * FROM accounts WHERE email = ?1 COLLATE NOCASE")
            .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
        stmt.query_row(params![email], |row| self.row_to_account(row))
            .optional()
            .map_err(|e| AppError::Config(format!("get_by_email: {}", e)))
    }

    pub fn email_exists(&self, email: &str) -> AppResult<bool> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE email = ?1 COLLATE NOCASE",
            params![email],
            |row| row.get(0),
        ).map_err(|e| AppError::Config(format!("email_exists: {}", e)))?;
        Ok(count > 0)
    }

    pub fn delete_account(&self, id: &Uuid) -> AppResult<bool> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let affected = conn.execute("DELETE FROM accounts WHERE id = ?1", params![id.to_string()])
            .map_err(|e| AppError::Config(format!("delete: {}", e)))?;
        if affected > 0 {
            self.invalidate_count_cache();  // P2: 总数减 1
        }
        Ok(affected > 0)
    }

    pub fn delete_accounts_batch(&self, ids: &[Uuid]) -> AppResult<Vec<Uuid>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut deleted = Vec::new();
        for id in ids {
            let affected = conn.execute("DELETE FROM accounts WHERE id = ?1", params![id.to_string()])
                .map_err(|e| AppError::Config(format!("batch_delete: {}", e)))?;
            if affected > 0 {
                deleted.push(*id);
            }
        }
        if !deleted.is_empty() {
            self.invalidate_count_cache();  // P2: 总数减 N
        }
        Ok(deleted)
    }

    pub fn get_all_accounts(&self) -> AppResult<Vec<Account>> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut stmt = conn.prepare("SELECT * FROM accounts ORDER BY sort_order ASC, created_at ASC")
            .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
        let accounts = stmt.query_map([], |row| self.row_to_account(row))
            .map_err(|e| AppError::Config(format!("query: {}", e)))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| AppError::Config("Account read/decryption failed; no records were discarded".into()))?;
        Ok(accounts)
    }

    /// 按 ID 列表精准查询账号（避免全量拉取再前端筛选）。
    /// 自动分批查询（每批 500），规避 SQLite 32766 变量数限制。
    pub fn get_accounts_by_ids(&self, ids: &[String]) -> AppResult<Vec<Account>> {
        if ids.is_empty() { return Ok(vec![]); }
        const BATCH_SIZE: usize = 500;
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut all_accounts: Vec<Account> = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(BATCH_SIZE) {
            let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("?{}", i)).collect();
            let sql = format!("SELECT * FROM accounts WHERE id IN ({}) ORDER BY sort_order ASC, created_at ASC", placeholders.join(","));
            let mut stmt = conn.prepare(&sql).map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
            for (i, id) in chunk.iter().enumerate() {
                stmt.raw_bind_parameter(i + 1, id.as_str()).map_err(|e| AppError::Config(format!("bind: {}", e)))?;
            }
            let batch: Vec<Account> = stmt.raw_query()
                .mapped(|row| self.row_to_account(row))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| AppError::Config("Account read/decryption failed".into()))?;
            all_accounts.extend(batch);
        }
        Ok(all_accounts)
    }

    /// 获取账号 ID 列表（轻量查询，不传完整数据）。
    /// `group` 有值时只返回该分组的 ID，`None` 时返回全部。
    pub fn get_all_ids(&self, group: Option<&str>) -> AppResult<Vec<String>> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        match group {
            Some(g) => {
                let mut stmt = conn.prepare(r#"SELECT id FROM accounts WHERE "group" = ?1 ORDER BY sort_order ASC, created_at ASC"#)
                    .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
                let ids: Vec<String> = stmt.query_map(params![g], |row| row.get::<_, String>(0))
                    .map_err(|e| AppError::Config(format!("query: {}", e)))?
                    .filter_map(|r| r.ok()).collect();
                Ok(ids)
            }
            None => {
                let mut stmt = conn.prepare("SELECT id FROM accounts ORDER BY sort_order ASC, created_at ASC")
                    .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
                let ids: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| AppError::Config(format!("query: {}", e)))?
                    .filter_map(|r| r.ok()).collect();
                Ok(ids)
            }
        }
    }

    pub fn count(&self) -> AppResult<u64> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
            .map_err(|e| AppError::Config(format!("count: {}", e)))?;
        Ok(count as u64)
    }

    // ==================== 分页查询 ====================

    /// 分页查询 + 服务端过滤/排序，替代前端 filteredAccounts computed。
    pub fn get_accounts_page(&self, req: &AccountPageRequest) -> AppResult<AccountPageResponse> {
        // P2: 在 conn lock 之前检查 COUNT 缓存，避免与 conn lock 交叉
        let cache_key = Self::hash_filter(req);
        let cached_total = self.get_cached_count(cache_key);

        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;

        let mut where_clauses: Vec<String> = Vec::new();
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut bind_idx = 1u32;

        // 搜索
        if let Some(ref search) = req.search {
            if !search.is_empty() {
                let pattern = format!("%{}%", search);
                where_clauses.push(format!(
                    "(email LIKE ?{idx} COLLATE NOCASE OR nickname LIKE ?{idx} COLLATE NOCASE OR tags LIKE ?{idx} COLLATE NOCASE)",
                    idx = bind_idx
                ));
                bind_values.push(Box::new(pattern));
                bind_idx += 1;
            }
        }

        // 分组
        if let Some(ref group) = req.group {
            if !group.is_empty() {
                where_clauses.push(format!(r#""group" = ?{}"#, bind_idx));
                bind_values.push(Box::new(group.clone()));
                bind_idx += 1;
            }
        }

        // 标签（任一匹配，用 OR + LIKE）
        if let Some(ref tags) = req.tags {
            if !tags.is_empty() {
                let tag_conditions: Vec<String> = tags.iter().enumerate().map(|(i, _tag)| {
                    let idx = bind_idx + i as u32;
                    format!("tags LIKE ?{} COLLATE NOCASE", idx)
                }).collect();
                where_clauses.push(format!("({})", tag_conditions.join(" OR ")));
                for tag in tags {
                    bind_values.push(Box::new(format!("%\"{}%", tag)));
                    bind_idx += 1;
                }
            }
        }

        // 套餐名
        if let Some(ref plans) = req.plan_names {
            if !plans.is_empty() {
                let placeholders: Vec<String> = plans.iter().enumerate().map(|(i, _)| {
                    format!("?{}", bind_idx + i as u32)
                }).collect();
                where_clauses.push(format!("plan_name IN ({})", placeholders.join(",")));
                for p in plans {
                    bind_values.push(Box::new(p.clone()));
                    bind_idx += 1;
                }
            }
        }

        // 域名
        if let Some(ref domains) = req.domains {
            if !domains.is_empty() {
                let domain_conditions: Vec<String> = domains.iter().enumerate().map(|(i, _)| {
                    format!("email LIKE ?{} COLLATE NOCASE", bind_idx + i as u32)
                }).collect();
                where_clauses.push(format!("({})", domain_conditions.join(" OR ")));
                for d in domains {
                    bind_values.push(Box::new(format!("%@{}", d)));
                    bind_idx += 1;
                }
            }
        }

        // 额度范围
        if let Some(min) = req.remaining_quota_min {
            where_clauses.push(format!("(COALESCE(total_quota, 0) - COALESCE(used_quota, 0)) >= ?{}", bind_idx));
            bind_values.push(Box::new(min * 100));
            bind_idx += 1;
        }
        if let Some(max) = req.remaining_quota_max {
            where_clauses.push(format!("(COALESCE(total_quota, 0) - COALESCE(used_quota, 0)) <= ?{}", bind_idx));
            bind_values.push(Box::new(max * 100));
            bind_idx += 1;
        }
        if let Some(min) = req.total_quota_min {
            where_clauses.push(format!("COALESCE(total_quota, 0) >= ?{}", bind_idx));
            bind_values.push(Box::new(min * 100));
            bind_idx += 1;
        }
        if let Some(max) = req.total_quota_max {
            where_clauses.push(format!("COALESCE(total_quota, 0) <= ?{}", bind_idx));
            bind_values.push(Box::new(max * 100));
            bind_idx += 1;
        }

        // 日/周配额百分比
        if let Some(min) = req.daily_quota_percent_min {
            where_clauses.push(format!("daily_quota_remaining_percent >= ?{}", bind_idx));
            bind_values.push(Box::new(min));
            bind_idx += 1;
        }
        if let Some(max) = req.daily_quota_percent_max {
            where_clauses.push(format!("daily_quota_remaining_percent <= ?{}", bind_idx));
            bind_values.push(Box::new(max));
            bind_idx += 1;
        }
        if let Some(min) = req.weekly_quota_percent_min {
            where_clauses.push(format!("weekly_quota_remaining_percent >= ?{}", bind_idx));
            bind_values.push(Box::new(min));
            bind_idx += 1;
        }
        if let Some(max) = req.weekly_quota_percent_max {
            where_clauses.push(format!("weekly_quota_remaining_percent <= ?{}", bind_idx));
            bind_values.push(Box::new(max));
            bind_idx += 1;
        }

        // 状态过滤（normal/offline/error/disabled/inactive）
        // 用 CASE 表达式计算复合状态，然后 IN 匹配用户选择的状态类型
        if let Some(ref statuses) = req.statuses {
            if !statuses.is_empty() {
                let placeholders: Vec<String> = statuses.iter().enumerate().map(|(i, _)| {
                    format!("?{}", bind_idx + i as u32)
                }).collect();
                where_clauses.push(format!("({}) IN ({})", Self::STATUS_CASE_EXPR, placeholders.join(",")));
                for s in statuses {
                    bind_values.push(Box::new(s.clone()));
                    bind_idx += 1;
                }
            }
        }

        // 剩余天数过滤（subscription_expires_at 与当前时间的差值）
        // 用 julianday 计算天数差，SUBSTR 截取前 19 位去除时区后缀以兼容 SQLite 日期函数
        if let Some(min) = req.expiry_days_min {
            where_clauses.push(format!(
                "subscription_expires_at IS NOT NULL AND CAST((julianday(SUBSTR(subscription_expires_at, 1, 19)) - julianday('now')) AS INTEGER) >= ?{}",
                bind_idx
            ));
            bind_values.push(Box::new(min));
            bind_idx += 1;
        }
        if let Some(max) = req.expiry_days_max {
            where_clauses.push(format!(
                "subscription_expires_at IS NOT NULL AND CAST((julianday(SUBSTR(subscription_expires_at, 1, 19)) - julianday('now')) AS INTEGER) <= ?{}",
                bind_idx
            ));
            bind_values.push(Box::new(max));
            bind_idx += 1;
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // 排序
        let order_col = match req.sort_field.as_deref() {
            Some("email") => "email COLLATE NOCASE",
            Some("used_quota") => "COALESCE(used_quota, 0)",
            Some("remaining_quota") => "(COALESCE(total_quota, 0) - COALESCE(used_quota, 0))",
            Some("token_expires_at") => "token_expires_at",
            Some("subscription_expires_at") => "subscription_expires_at",
            Some("plan_name") => "plan_name",
            Some("daily_quota_remaining") => "COALESCE(daily_quota_remaining_percent, -1)",
            Some("weekly_quota_remaining") => "COALESCE(weekly_quota_remaining_percent, -1)",
            _ => "sort_order ASC, created_at",
        };
        let order_dir = match req.sort_direction.as_deref() {
            Some("desc") => "DESC",
            _ => "ASC",
        };

        let bind_refs: Vec<&dyn rusqlite::types::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();

        // P2: COUNT 缓存命中则复用，否则查询 SQL COUNT(*)「节省 20-100ms / 翻页」
        let total: i64 = if let Some(t) = cached_total {
            t
        } else {
            let count_sql = format!("SELECT COUNT(*) FROM accounts {}", where_sql);
            conn.query_row(&count_sql, bind_refs.as_slice(), |row| row.get(0))
                .map_err(|e| AppError::Config(format!("count query: {}", e)))?
        };

        // Page data
        let page = req.page.max(1);
        let page_size = req.page_size.clamp(1, 500);
        let offset = (page - 1) * page_size;

        let data_sql = format!(
            "SELECT * FROM accounts {} ORDER BY {} {} LIMIT {} OFFSET {}",
            where_sql, order_col, order_dir, page_size, offset
        );

        let mut stmt = conn.prepare(&data_sql)
            .map_err(|e| AppError::Config(format!("prepare page: {}", e)))?;

        let accounts: Vec<Account> = stmt.query_map(bind_refs.as_slice(), |row| self.row_to_account(row))
            .map_err(|e| AppError::Config(format!("page query: {}", e)))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| AppError::Config("Account read/decryption failed".into()))?;

        // 释放 conn lock（drop stmt + conn）后再写 count_cache，避免 Mutex 交叉持有
        drop(stmt);
        drop(conn);

        // P2: 首次查询才回填缓存（命中路径不重复写）
        if cached_total.is_none() {
            self.set_cached_count(cache_key, total);
        }

        Ok(AccountPageResponse {
            accounts,
            total: total as u64,
            page,
            page_size,
        })
    }

    // ==================== 聚合统计 ====================

    /// 获取聚合统计（分组列表、套餐列表、域名列表、标签列表、总数、活跃数）。
    /// 前端下拉框 / 统计面板使用，替代原 6 个 computed 各遍历 10 万对象。
    pub fn get_aggregates(&self) -> AppResult<AccountAggregates> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;

        let total_count: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
            .unwrap_or(0);

        let active_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE status = '\"active\"'", [], |r| r.get(0)
        ).unwrap_or(0);

        let groups = Self::collect_distinct(&conn,
            r#"SELECT DISTINCT "group" FROM accounts WHERE "group" IS NOT NULL AND "group" != '' ORDER BY "group""#);

        let plan_names = Self::collect_distinct(&conn,
            "SELECT DISTINCT plan_name FROM accounts WHERE plan_name IS NOT NULL AND plan_name != '' ORDER BY plan_name");

        // 域名：用 substr + instr 提取 @ 后部分
        let domains = Self::collect_distinct(&conn,
            "SELECT DISTINCT SUBSTR(email, INSTR(email, '@') + 1) as domain FROM accounts WHERE INSTR(email, '@') > 0 ORDER BY domain");

        // 标签：从 JSON 数组中提取（需要 json_each，SQLite 3.38+）
        // 回退方案：在 Rust 侧解析
        let tags = Self::collect_tags_from_json(&conn);

        // 每个分组的账号数量（供侧边栏分组列表 "xxx (N)" 显示）
        let group_counts = Self::collect_group_counts(&conn);

        // 每个标签的使用次数（供标签管理页面 "xxx (N)" 显示）
        let tag_counts = Self::collect_tag_counts(&conn);

        Ok(AccountAggregates {
            total_count: total_count as u64,
            groups,
            plan_names,
            domains,
            tags,
            active_count: active_count as u64,
            group_counts,
            tag_counts,
        })
    }

    // ==================== 批量操作 ====================

    /// 按 ID 列表批量更改分组（供前端跨页选中批量操作使用）。
    /// 自动分批执行（每批 499 个 ID），规避 SQLite 32766 变量数限制。
    pub fn update_group_by_ids(&self, ids: &[String], group: &str) -> AppResult<usize> {
        if ids.is_empty() { return Ok(0); }
        const BATCH_SIZE: usize = 499; // +1 group 参数 = 500
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut total_affected: usize = 0;
        for chunk in ids.chunks(BATCH_SIZE) {
            let placeholders: Vec<String> = chunk.iter().enumerate().map(|(i, _)| format!("?{}", i + 2)).collect();
            let sql = format!(r#"UPDATE accounts SET "group" = ?1 WHERE id IN ({})"#, placeholders.join(","));
            let mut stmt = conn.prepare(&sql).map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
            let mut param_idx: usize = 1;
            stmt.raw_bind_parameter(param_idx, group).map_err(|e| AppError::Config(format!("bind: {}", e)))?;
            for id in chunk {
                param_idx += 1;
                stmt.raw_bind_parameter(param_idx, id.as_str()).map_err(|e| AppError::Config(format!("bind: {}", e)))?;
            }
            total_affected += stmt.raw_execute().map_err(|e| AppError::Config(format!("execute: {}", e)))?;
        }
        if total_affected > 0 {
            self.invalidate_count_cache();  // P2: group filter 命中变化
        }
        Ok(total_affected)
    }

    /// 批量更新分组（用于分组重命名时同步所有账号）
    pub fn update_group_for_all(&self, old_group: &str, new_group: Option<&str>) -> AppResult<usize> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let affected = conn.execute(
            r#"UPDATE accounts SET "group" = ?1 WHERE "group" = ?2"#,
            params![new_group, old_group],
        ).map_err(|e| AppError::Config(format!("update_group: {}", e)))?;
        if affected > 0 {
            self.invalidate_count_cache();  // P2: group filter 命中变化
        }
        Ok(affected)
    }

    /// 批量更新标签（用于标签重命名时同步所有账号）
    pub fn rename_tag_for_all(&self, old_name: &str, new_name: &str) -> AppResult<usize> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        // 先查出所有包含该标签的账号
        let mut stmt = conn.prepare("SELECT id, tags, tag_colors FROM accounts WHERE tags LIKE ?1")
            .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
        let pattern = format!("%\"{}%", old_name);
        let rows: Vec<(String, String, String)> = stmt.query_map(params![pattern], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        }).map_err(|e| AppError::Config(format!("query: {}", e)))?
          .filter_map(|r| r.ok())
          .collect();

        let mut count = 0usize;
        for (id, tags_json, colors_json) in &rows {
            let mut tags: Vec<String> = serde_json::from_str(tags_json).unwrap_or_default();
            let mut colors: Vec<TagWithColor> = serde_json::from_str(colors_json).unwrap_or_default();
            let mut changed = false;

            for tag in &mut tags {
                if tag == old_name {
                    *tag = new_name.to_string();
                    changed = true;
                }
            }
            for tc in &mut colors {
                if tc.name == old_name {
                    tc.name = new_name.to_string();
                    changed = true;
                }
            }

            if changed {
                conn.execute(
                    "UPDATE accounts SET tags = ?1, tag_colors = ?2 WHERE id = ?3",
                    params![
                        serde_json::to_string(&tags).unwrap_or_default(),
                        serde_json::to_string(&colors).unwrap_or_default(),
                        id,
                    ],
                ).map_err(|e| AppError::Config(format!("update tag: {}", e)))?;
                count += 1;
            }
        }
        if count > 0 {
            self.invalidate_count_cache();  // P2: tag filter 命中变化
        }
        Ok(count)
    }

    /// 批量删除标签（用于标签删除时从所有账号移除）
    pub fn remove_tag_for_all(&self, tag_name: &str) -> AppResult<usize> {
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        let mut stmt = conn.prepare("SELECT id, tags, tag_colors FROM accounts WHERE tags LIKE ?1")
            .map_err(|e| AppError::Config(format!("prepare: {}", e)))?;
        let pattern = format!("%\"{}%", tag_name);
        let rows: Vec<(String, String, String)> = stmt.query_map(params![pattern], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        }).map_err(|e| AppError::Config(format!("query: {}", e)))?
          .filter_map(|r| r.ok())
          .collect();

        let mut count = 0usize;
        for (id, tags_json, colors_json) in &rows {
            let mut tags: Vec<String> = serde_json::from_str(tags_json).unwrap_or_default();
            let mut colors: Vec<TagWithColor> = serde_json::from_str(colors_json).unwrap_or_default();
            let orig_len = tags.len();

            tags.retain(|t| t != tag_name);
            colors.retain(|tc| tc.name != tag_name);

            if tags.len() != orig_len {
                conn.execute(
                    "UPDATE accounts SET tags = ?1, tag_colors = ?2 WHERE id = ?3",
                    params![
                        serde_json::to_string(&tags).unwrap_or_default(),
                        serde_json::to_string(&colors).unwrap_or_default(),
                        id,
                    ],
                ).map_err(|e| AppError::Config(format!("remove tag: {}", e)))?;
                count += 1;
            }
        }
        if count > 0 {
            self.invalidate_count_cache();  // P2: tag filter 命中变化
        }
        Ok(count)
    }

    /// 批量导入账号（迁移用，事务内批量 INSERT）
    pub fn bulk_insert(&self, accounts: &[Account]) -> AppResult<usize> {
        let accounts = accounts.iter().map(|a| self.seal_account(a)).collect::<AppResult<Vec<_>>>()?;
        let conn = self.conn.lock().map_err(|e| AppError::Config(format!("lock: {}", e)))?;
        conn.execute("BEGIN TRANSACTION", [])
            .map_err(|e| AppError::Config(format!("begin: {}", e)))?;

        let mut count = 0usize;
        for account in accounts {
            let result = conn.execute(
                r#"INSERT OR IGNORE INTO accounts (
                    id, email, password, nickname, tags, tag_colors, "group",
                    token, refresh_token, token_expires_at, last_seat_count,
                    created_at, last_login_at, status, plan_name, used_quota, total_quota,
                    last_quota_update, subscription_expires_at, subscription_active,
                    windsurf_api_key, is_disabled, is_team_owner, billing_strategy,
                    daily_quota_remaining_percent, weekly_quota_remaining_percent,
                    daily_quota_reset_at_unix, weekly_quota_reset_at_unix,
                    overage_balance_micros, sort_order,
                    devin_auth1_token, devin_account_id, devin_primary_org_id, auth_provider
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                    ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?17,
                    ?18, ?19, ?20,
                    ?21, ?22, ?23, ?24,
                    ?25, ?26,
                    ?27, ?28,
                    ?29, ?30,
                    ?31, ?32, ?33, ?34
                )"#,
                params![
                    account.id.to_string(),
                    account.email,
                    account.password,
                    account.nickname,
                    serde_json::to_string(&account.tags).unwrap_or_default(),
                    serde_json::to_string(&account.tag_colors).unwrap_or_default(),
                    account.group,
                    account.token,
                    account.refresh_token,
                    account.token_expires_at.map(|t| t.to_rfc3339()),
                    account.last_seat_count,
                    account.created_at.to_rfc3339(),
                    account.last_login_at.map(|t| t.to_rfc3339()),
                    serde_json::to_string(&account.status).unwrap_or_default(),
                    account.plan_name,
                    account.used_quota,
                    account.total_quota,
                    account.last_quota_update.map(|t| t.to_rfc3339()),
                    account.subscription_expires_at.map(|t| t.to_rfc3339()),
                    account.subscription_active.map(|b| b as i32),
                    account.windsurf_api_key,
                    account.is_disabled.map(|b| b as i32),
                    account.is_team_owner.map(|b| b as i32),
                    account.billing_strategy,
                    account.daily_quota_remaining_percent,
                    account.weekly_quota_remaining_percent,
                    account.daily_quota_reset_at_unix,
                    account.weekly_quota_reset_at_unix,
                    account.overage_balance_micros,
                    account.sort_order,
                    account.devin_auth1_token,
                    account.devin_account_id,
                    account.devin_primary_org_id,
                    account.auth_provider,
                ],
            );
            if result.is_ok() {
                count += 1;
            }
        }

        conn.execute("COMMIT", [])
            .map_err(|e| AppError::Config(format!("commit: {}", e)))?;
        if count > 0 {
            self.invalidate_count_cache();  // P2: 总数增加
        }
        Ok(count)
    }

    // ==================== 内部辅助 ====================

    fn row_to_account(&self, row: &rusqlite::Row) -> rusqlite::Result<Account> {
        let id_str: String = row.get("id")?;
        let tags_json: String = row.get("tags")?;
        let tag_colors_json: String = row.get("tag_colors")?;
        let status_json: String = row.get("status")?;

        let token_expires_at: Option<String> = row.get("token_expires_at")?;
        let created_at_str: String = row.get("created_at")?;
        let last_login_at: Option<String> = row.get("last_login_at")?;
        let last_quota_update: Option<String> = row.get("last_quota_update")?;
        let subscription_expires_at: Option<String> = row.get("subscription_expires_at")?;

        let subscription_active: Option<i32> = row.get("subscription_active")?;
        let is_disabled: Option<i32> = row.get("is_disabled")?;
        let is_team_owner: Option<i32> = row.get("is_team_owner")?;

        Ok(Account {
            id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4()),
            email: row.get("email")?,
            password: self.unseal(row.get::<_, String>("password")?)?,
            nickname: row.get("nickname")?,
            tags: serde_json::from_str(&tags_json).unwrap_or_default(),
            tag_colors: serde_json::from_str(&tag_colors_json).unwrap_or_default(),
            group: row.get("group")?,
            token: row.get::<_, Option<String>>("token")?.map(|v| self.unseal(v)).transpose()?,
            refresh_token: row.get::<_, Option<String>>("refresh_token")?.map(|v| self.unseal(v)).transpose()?,
            token_expires_at: token_expires_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&Utc)),
            last_seat_count: row.get("last_seat_count")?,
            created_at: DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_login_at: last_login_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&Utc)),
            status: serde_json::from_str(&status_json).unwrap_or(AccountStatus::Inactive),
            plan_name: row.get("plan_name")?,
            used_quota: row.get("used_quota")?,
            total_quota: row.get("total_quota")?,
            last_quota_update: last_quota_update.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&Utc)),
            subscription_expires_at: subscription_expires_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&Utc)),
            subscription_active: subscription_active.map(|v| v != 0),
            windsurf_api_key: row.get::<_, Option<String>>("windsurf_api_key")?.map(|v| self.unseal(v)).transpose()?,
            is_disabled: is_disabled.map(|v| v != 0),
            is_team_owner: is_team_owner.map(|v| v != 0),
            billing_strategy: row.get("billing_strategy")?,
            daily_quota_remaining_percent: row.get("daily_quota_remaining_percent")?,
            weekly_quota_remaining_percent: row.get("weekly_quota_remaining_percent")?,
            daily_quota_reset_at_unix: row.get("daily_quota_reset_at_unix")?,
            weekly_quota_reset_at_unix: row.get("weekly_quota_reset_at_unix")?,
            overage_balance_micros: row.get("overage_balance_micros")?,
            sort_order: row.get("sort_order")?,
            devin_auth1_token: row.get::<_, Option<String>>("devin_auth1_token")?.map(|v| self.unseal(v)).transpose()?,
            devin_account_id: row.get("devin_account_id")?,
            devin_primary_org_id: row.get("devin_primary_org_id")?,
            auth_provider: row.get("auth_provider")?,
            parent_account_id: {
                let s: Option<String> = row.get("parent_account_id")?;
                s.and_then(|v| Uuid::parse_str(&v).ok())
            },
            devin_org_id: row.get("devin_org_id")?,
            devin_org_name: row.get("devin_org_name")?,
        })
    }

    fn collect_distinct(conn: &Connection, sql: &str) -> Vec<String> {
        conn.prepare(sql)
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
                Ok(rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default()
    }

    fn collect_tags_from_json(conn: &Connection) -> Vec<String> {
        // 尝试使用 json_each（SQLite 3.38+），回退到 Rust 侧解析
        let result = conn.prepare("SELECT DISTINCT j.value FROM accounts, json_each(accounts.tags) AS j ORDER BY j.value");
        match result {
            Ok(mut stmt) => {
                stmt.query_map([], |row| row.get::<_, String>(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default()
            }
            Err(_) => {
                // json_each 不可用，回退
                let mut tag_set = std::collections::BTreeSet::new();
                if let Ok(mut stmt) = conn.prepare("SELECT tags FROM accounts") {
                    if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                        for tags_json in rows.filter_map(|r| r.ok()) {
                            if let Ok(tags) = serde_json::from_str::<Vec<String>>(&tags_json) {
                                for tag in tags {
                                    tag_set.insert(tag);
                                }
                            }
                        }
                    }
                }
                tag_set.into_iter().collect()
            }
        }
    }

    /// 统计每个标签被多少账号使用（供标签管理页面 "xxx (N)" 显示）
    fn collect_tag_counts(conn: &Connection) -> std::collections::HashMap<String, u64> {
        let mut counts = std::collections::HashMap::new();
        // 尝试 json_each（SQLite 3.38+），回退到 Rust 侧解析
        let result = conn.prepare(
            "SELECT j.value, COUNT(*) FROM accounts, json_each(accounts.tags) AS j GROUP BY j.value"
        );
        match result {
            Ok(mut stmt) => {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.filter_map(|r| r.ok()) {
                        counts.insert(row.0, row.1 as u64);
                    }
                }
            }
            Err(_) => {
                // json_each 不可用，回退到 Rust 侧解析
                if let Ok(mut stmt) = conn.prepare("SELECT tags FROM accounts") {
                    if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                        for tags_json in rows.filter_map(|r| r.ok()) {
                            if let Ok(tags) = serde_json::from_str::<Vec<String>>(&tags_json) {
                                for tag in tags {
                                    *counts.entry(tag).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        counts
    }

    /// 查询每个分组的账号数量（供侧边栏 "xxx (N)" 显示）
    fn collect_group_counts(conn: &Connection) -> std::collections::HashMap<String, u64> {
        let mut counts = std::collections::HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            r#"SELECT COALESCE("group", '默认分组') as g, COUNT(*) as c FROM accounts GROUP BY g ORDER BY g"#
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.filter_map(|r| r.ok()) {
                    counts.insert(row.0, row.1 as u64);
                }
            }
        }
        counts
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    fn store() -> SqliteAccountStore {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SqliteAccountStore::CREATE_SCHEMA).unwrap();
        SqliteAccountStore::migrate_columns(&conn);
        SqliteAccountStore { conn: Mutex::new(conn), crypto: CryptoService::for_test(), count_cache: Mutex::new(HashMap::new()) }
    }
    #[test]
    fn credentials_roundtrip_and_migration() {
        let store = store();
        let mut a = Account::new("test@example.invalid".into(), "test-password".into(), "test".into(), vec![]);
        a.token = Some("test-token".into());
        a.refresh_token = Some("test-refresh".into());
        a.windsurf_api_key = Some("test-api-key".into());
        a.devin_auth1_token = Some("test-auth1".into());
        store.insert_account(&a).unwrap();
        let read = store.get_account(&a.id).unwrap();
        assert_eq!(read.password, a.password);
        assert_eq!(read.token, a.token);
        assert_eq!(read.refresh_token, a.refresh_token);
        assert_eq!(read.windsurf_api_key, a.windsurf_api_key);
        assert_eq!(read.devin_auth1_token, a.devin_auth1_token);
        {
            let conn = store.conn.lock().unwrap();
            for col in ["password", "token", "refresh_token", "windsurf_api_key", "devin_auth1_token"] {
                let raw: String = conn.query_row(&format!("SELECT {} FROM accounts", col), [], |r| r.get(0)).unwrap();
                assert!(raw.starts_with("wam:v1:"));
            }
            conn.execute("UPDATE accounts SET password='legacy-test'", []).unwrap();
        }
        store.migrate_credentials().unwrap();
        store.migrate_credentials().unwrap();
        assert_eq!(store.get_account(&a.id).unwrap().password, "legacy-test");
        store.upsert_account(&a).unwrap();
        assert_eq!(store.get_account(&a.id).unwrap().token, a.token);
    }
    #[test]
    fn bulk_import_preserves_empty_fields_and_rejects_wrong_key() {
        let mut store = store();
        let mut a = Account::new("bulk@example.invalid".into(), "".into(), "test".into(), vec![]);
        a.token = Some(String::new());
        a.windsurf_api_key = Some("test-key".into());
        assert_eq!(store.bulk_insert(&[a.clone()]).unwrap(), 1);
        let read = store.get_account(&a.id).unwrap();
        assert_eq!(read.password, "");
        assert_eq!(read.token, Some(String::new()));
        assert_eq!(read.refresh_token, None);
        assert_eq!(read.windsurf_api_key, a.windsurf_api_key);
        store.crypto = CryptoService::for_test();
        assert!(store.get_account(&a.id).is_err());
        assert!(store.get_all_accounts().is_err());
        assert!(store.migrate_credentials().is_err());
    }

    #[test]
    fn corrupt_credentials_abort_migration_without_partial_changes() {
        let store = store();
        let a = Account::new("test@example.invalid".into(), "test".into(), "test".into(), vec![]);
        store.insert_account(&a).unwrap();
        store.conn.lock().unwrap().execute("UPDATE accounts SET password='legacy', token='wam:v1:broken'", []).unwrap();
        assert!(store.migrate_credentials().is_err());
        let raw: String = store.conn.lock().unwrap().query_row("SELECT password FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(raw, "legacy");
        assert!(store.get_account(&a.id).is_err());
    }
}
