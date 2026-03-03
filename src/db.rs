use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub proxy_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyRow {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: i32,
    pub config_json: String,
    pub is_valid: bool,
    pub local_port: Option<i32>,
    pub error_count: i32,
    pub last_error: Option<String>,
    pub last_validated: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyQuality {
    pub proxy_id: String,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub ip_type: Option<String>,
    pub is_residential: bool,
    pub chatgpt_accessible: bool,
    pub google_accessible: bool,
    pub risk_score: f64,
    pub risk_level: String,
    pub extra_json: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub name: Option<String>,
    pub avatar_template: Option<String>,
    pub active: bool,
    pub trust_level: i32,
    pub silenced: bool,
    pub is_banned: bool,
    pub api_key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: String,
    pub expires_at: String,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sub_type TEXT NOT NULL,
                url TEXT,
                content TEXT,
                proxy_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                subscription_id TEXT NOT NULL,
                name TEXT NOT NULL,
                proxy_type TEXT NOT NULL,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                is_valid INTEGER DEFAULT 0,
                local_port INTEGER,
                error_count INTEGER DEFAULT 0,
                last_error TEXT,
                last_validated TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proxy_quality (
                proxy_id TEXT PRIMARY KEY,
                ip_address TEXT,
                country TEXT,
                ip_type TEXT,
                is_residential INTEGER DEFAULT 0,
                chatgpt_accessible INTEGER DEFAULT 0,
                google_accessible INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 1.0,
                risk_level TEXT DEFAULT 'Unknown',
                extra_json TEXT,
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                name TEXT,
                avatar_template TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                trust_level INTEGER NOT NULL DEFAULT 0,
                silenced INTEGER NOT NULL DEFAULT 0,
                is_banned INTEGER NOT NULL DEFAULT 0,
                api_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
            ",
        )?;
        Ok(())
    }

    // --- Subscription CRUD ---

    pub fn insert_subscription(&self, sub: &Subscription) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO subscriptions (id, name, sub_type, url, content, proxy_count, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![sub.id, sub.name, sub.sub_type, sub.url, sub.content, sub.proxy_count, sub.created_at, sub.updated_at],
        )?;
        Ok(())
    }

    pub fn get_subscriptions(&self) -> Result<Vec<Subscription>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, sub_type, url, content, proxy_count, created_at, updated_at FROM subscriptions ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(Subscription {
                id: row.get(0)?,
                name: row.get(1)?,
                sub_type: row.get(2)?,
                url: row.get(3)?,
                content: row.get(4)?,
                proxy_count: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name, sub_type, url, content, proxy_count, created_at, updated_at FROM subscriptions WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Subscription {
                id: row.get(0)?,
                name: row.get(1)?,
                sub_type: row.get(2)?,
                url: row.get(3)?,
                content: row.get(4)?,
                proxy_count: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn delete_subscription(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM proxy_quality WHERE proxy_id IN (SELECT id FROM proxies WHERE subscription_id = ?1)", params![id])?;
        conn.execute("DELETE FROM proxies WHERE subscription_id = ?1", params![id])?;
        conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn update_subscription_proxy_count(&self, sub_id: &str, count: i32) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE subscriptions SET proxy_count = ?1, updated_at = ?2 WHERE id = ?3",
            params![count, now, sub_id],
        )?;
        Ok(())
    }

    // --- Proxy CRUD ---

    pub fn insert_proxy(&self, proxy: &ProxyRow) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO proxies (id, subscription_id, name, proxy_type, server, port, config_json, is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                proxy.id, proxy.subscription_id, proxy.name, proxy.proxy_type,
                proxy.server, proxy.port, proxy.config_json, proxy.is_valid as i32,
                proxy.local_port, proxy.error_count, proxy.last_error,
                proxy.last_validated, proxy.created_at, proxy.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_all_proxies(&self) -> Result<Vec<ProxyRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subscription_id, name, proxy_type, server, port, config_json, is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at
             FROM proxies ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProxyRow {
                id: row.get(0)?,
                subscription_id: row.get(1)?,
                name: row.get(2)?,
                proxy_type: row.get(3)?,
                server: row.get(4)?,
                port: row.get(5)?,
                config_json: row.get(6)?,
                is_valid: row.get::<_, i32>(7)? != 0,
                local_port: row.get(8)?,
                error_count: row.get(9)?,
                last_error: row.get(10)?,
                last_validated: row.get(11)?,
                created_at: row.get(12)?,
                updated_at: row.get(13)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_proxies_by_subscription(&self, sub_id: &str) -> Result<Vec<ProxyRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subscription_id, name, proxy_type, server, port, config_json, is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at
             FROM proxies WHERE subscription_id = ?1 ORDER BY name"
        )?;
        let rows = stmt.query_map(params![sub_id], |row| {
            Ok(ProxyRow {
                id: row.get(0)?,
                subscription_id: row.get(1)?,
                name: row.get(2)?,
                proxy_type: row.get(3)?,
                server: row.get(4)?,
                port: row.get(5)?,
                config_json: row.get(6)?,
                is_valid: row.get::<_, i32>(7)? != 0,
                local_port: row.get(8)?,
                error_count: row.get(9)?,
                last_error: row.get(10)?,
                last_validated: row.get(11)?,
                created_at: row.get(12)?,
                updated_at: row.get(13)?,
            })
        })?;
        rows.collect()
    }

    pub fn delete_proxy(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM proxy_quality WHERE proxy_id = ?1", params![id])?;
        conn.execute("DELETE FROM proxies WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_proxies_by_subscription(&self, sub_id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM proxy_quality WHERE proxy_id IN (SELECT id FROM proxies WHERE subscription_id = ?1)", params![sub_id])?;
        conn.execute("DELETE FROM proxies WHERE subscription_id = ?1", params![sub_id])?;
        Ok(())
    }

    pub fn update_proxy_validation(&self, id: &str, is_valid: bool, error: Option<&str>) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        if is_valid {
            conn.execute(
                "UPDATE proxies SET is_valid = 1, error_count = 0, last_error = NULL, last_validated = ?1, updated_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
        } else {
            conn.execute(
                "UPDATE proxies SET is_valid = 0, error_count = error_count + 1, last_error = ?1, last_validated = ?2, updated_at = ?2 WHERE id = ?3",
                params![error, now, id],
            )?;
        }
        Ok(())
    }

    pub fn update_proxy_local_port(&self, id: &str, local_port: i32) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE proxies SET local_port = ?1 WHERE id = ?2",
            params![local_port, id],
        )?;
        Ok(())
    }

    pub fn increment_proxy_error_count(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE proxies SET error_count = error_count + 1, updated_at = ?1 WHERE id = ?2",
            params![chrono::Utc::now().to_rfc3339(), id],
        )?;
        Ok(())
    }

    pub fn update_proxy_config(&self, id: &str, name: &str, config_json: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE proxies SET name = ?1, config_json = ?2, updated_at = ?3 WHERE id = ?4",
            params![name, config_json, chrono::Utc::now().to_rfc3339(), id],
        )?;
        Ok(())
    }

    pub fn update_proxy_local_port_null(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE proxies SET local_port = NULL WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn clear_all_proxy_local_ports(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE proxies SET local_port = NULL", [])?;
        Ok(())
    }

    pub fn cleanup_high_error_proxies(&self, threshold: u32) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM proxy_quality WHERE proxy_id IN (SELECT id FROM proxies WHERE error_count >= ?1)", params![threshold])?;
        let count = conn.execute("DELETE FROM proxies WHERE error_count >= ?1", params![threshold])?;
        Ok(count)
    }

    // --- Quality ---

    pub fn upsert_quality(&self, q: &ProxyQuality) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO proxy_quality (proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                q.proxy_id, q.ip_address, q.country, q.ip_type,
                q.is_residential as i32, q.chatgpt_accessible as i32,
                q.google_accessible as i32, q.risk_score, q.risk_level,
                q.extra_json, q.checked_at
            ],
        )?;
        Ok(())
    }

    pub fn get_quality(&self, proxy_id: &str) -> Result<Option<ProxyQuality>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at
             FROM proxy_quality WHERE proxy_id = ?1"
        )?;
        let mut rows = stmt.query_map(params![proxy_id], |row| {
            Ok(ProxyQuality {
                proxy_id: row.get(0)?,
                ip_address: row.get(1)?,
                country: row.get(2)?,
                ip_type: row.get(3)?,
                is_residential: row.get::<_, i32>(4)? != 0,
                chatgpt_accessible: row.get::<_, i32>(5)? != 0,
                google_accessible: row.get::<_, i32>(6)? != 0,
                risk_score: row.get(7)?,
                risk_level: row.get(8)?,
                extra_json: row.get(9)?,
                checked_at: row.get(10)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn get_all_qualities(&self) -> Result<Vec<ProxyQuality>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at
             FROM proxy_quality"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProxyQuality {
                proxy_id: row.get(0)?,
                ip_address: row.get(1)?,
                country: row.get(2)?,
                ip_type: row.get(3)?,
                is_residential: row.get::<_, i32>(4)? != 0,
                chatgpt_accessible: row.get::<_, i32>(5)? != 0,
                google_accessible: row.get::<_, i32>(6)? != 0,
                risk_score: row.get(7)?,
                risk_level: row.get(8)?,
                extra_json: row.get(9)?,
                checked_at: row.get(10)?,
            })
        })?;
        rows.collect()
    }

    // --- Stats ---

    pub fn get_stats(&self) -> Result<serde_json::Value, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let total: i32 = conn.query_row("SELECT COUNT(*) FROM proxies", [], |r| r.get(0))?;
        let valid: i32 = conn.query_row("SELECT COUNT(*) FROM proxies WHERE is_valid = 1", [], |r| r.get(0))?;
        let untested: i32 = conn.query_row("SELECT COUNT(*) FROM proxies WHERE is_valid = 0 AND last_validated IS NULL", [], |r| r.get(0))?;
        let invalid: i32 = conn.query_row("SELECT COUNT(*) FROM proxies WHERE is_valid = 0 AND last_validated IS NOT NULL", [], |r| r.get(0))?;
        let subs: i32 = conn.query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))?;
        let quality_checked: i32 = conn.query_row("SELECT COUNT(*) FROM proxy_quality", [], |r| r.get(0))?;

        // By type
        let mut stmt = conn.prepare("SELECT proxy_type, COUNT(*) FROM proxies GROUP BY proxy_type")?;
        let by_type: Vec<(String, i32)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?.filter_map(|r| r.ok()).collect();

        // By country
        let mut stmt = conn.prepare("SELECT country, COUNT(*) FROM proxy_quality WHERE country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC")?;
        let by_country: Vec<(String, i32)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?.filter_map(|r| r.ok()).collect();

        Ok(serde_json::json!({
            "total_proxies": total,
            "valid_proxies": valid,
            "untested_proxies": untested,
            "invalid_proxies": invalid,
            "subscriptions": subs,
            "quality_checked": quality_checked,
            "by_type": by_type.into_iter().collect::<std::collections::HashMap<_, _>>(),
            "by_country": by_country.into_iter().collect::<std::collections::HashMap<_, _>>(),
        }))
    }

    // --- User CRUD ---

    pub fn upsert_user(&self, user: &User) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                name = excluded.name,
                avatar_template = excluded.avatar_template,
                active = excluded.active,
                trust_level = excluded.trust_level,
                silenced = excluded.silenced,
                updated_at = excluded.updated_at",
            params![
                user.id, user.username, user.name, user.avatar_template,
                user.active as i32, user.trust_level, user.silenced as i32,
                user.is_banned as i32, user.api_key, user.created_at, user.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<User>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at
             FROM users WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                name: row.get(2)?,
                avatar_template: row.get(3)?,
                active: row.get::<_, i32>(4)? != 0,
                trust_level: row.get(5)?,
                silenced: row.get::<_, i32>(6)? != 0,
                is_banned: row.get::<_, i32>(7)? != 0,
                api_key: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn get_user_by_api_key(&self, api_key: &str) -> Result<Option<User>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at
             FROM users WHERE api_key = ?1"
        )?;
        let mut rows = stmt.query_map(params![api_key], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                name: row.get(2)?,
                avatar_template: row.get(3)?,
                active: row.get::<_, i32>(4)? != 0,
                trust_level: row.get(5)?,
                silenced: row.get::<_, i32>(6)? != 0,
                is_banned: row.get::<_, i32>(7)? != 0,
                api_key: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn get_all_users(&self) -> Result<Vec<User>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at
             FROM users ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                name: row.get(2)?,
                avatar_template: row.get(3)?,
                active: row.get::<_, i32>(4)? != 0,
                trust_level: row.get(5)?,
                silenced: row.get::<_, i32>(6)? != 0,
                is_banned: row.get::<_, i32>(7)? != 0,
                api_key: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        rows.collect()
    }

    pub fn delete_user(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
        conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn set_user_banned(&self, id: &str, banned: bool) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE users SET is_banned = ?1, updated_at = ?2 WHERE id = ?3",
            params![banned as i32, now, id],
        )?;
        if banned {
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
        }
        Ok(())
    }

    pub fn regenerate_api_key(&self, user_id: &str) -> Result<String, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let new_key = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE users SET api_key = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_key, now, user_id],
        )?;
        Ok(new_key)
    }

    // --- Session CRUD ---

    pub fn create_session(&self, user_id: &str) -> Result<Session, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7);
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        };
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![session.id, session.user_id, session.created_at, session.expires_at],
        )?;
        Ok(session)
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Session {
                id: row.get(0)?,
                user_id: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn delete_session(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_user_sessions(&self, user_id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let count = conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])?;
        Ok(count)
    }
}
