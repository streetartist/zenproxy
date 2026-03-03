use crate::db::{Database, ProxyQuality};
use dashmap::DashMap;
use rand::seq::SliceRandom;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyStatus {
    Untested,
    Valid,
    Invalid,
}

impl ProxyStatus {
    /// Sort weight: Valid=0, Untested=1, Invalid=2 (lower = higher priority).
    pub fn sort_weight(self) -> u8 {
        match self {
            ProxyStatus::Valid => 0,
            ProxyStatus::Untested => 1,
            ProxyStatus::Invalid => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolProxy {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: u16,
    pub singbox_outbound: serde_json::Value,
    pub status: ProxyStatus,
    pub local_port: Option<u16>,
    pub error_count: u32,
    pub quality: Option<ProxyQualityInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyQualityInfo {
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub ip_type: Option<String>,
    pub is_residential: bool,
    pub chatgpt_accessible: bool,
    pub google_accessible: bool,
    pub risk_score: f64,
    pub risk_level: String,
    pub checked_at: Option<String>,
    #[serde(skip_serializing)]
    pub incomplete_retry_count: u8,
}

impl From<ProxyQuality> for ProxyQualityInfo {
    fn from(q: ProxyQuality) -> Self {
        let incomplete_retry_count = q
            .extra_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|v| v.get("incomplete_retry_count").and_then(|n| n.as_u64()))
            .map(|n| n.min(u8::MAX as u64) as u8)
            .unwrap_or(0);

        ProxyQualityInfo {
            ip_address: q.ip_address,
            country: q.country,
            ip_type: q.ip_type,
            is_residential: q.is_residential,
            chatgpt_accessible: q.chatgpt_accessible,
            google_accessible: q.google_accessible,
            risk_score: q.risk_score,
            risk_level: q.risk_level,
            checked_at: Some(q.checked_at),
            incomplete_retry_count,
        }
    }
}

pub struct ProxyPool {
    proxies: DashMap<String, PoolProxy>,
}

impl ProxyPool {
    pub fn new() -> Self {
        ProxyPool {
            proxies: DashMap::new(),
        }
    }

    pub fn load_from_db(&self, db: &Database) {
        let rows = db.get_all_proxies().unwrap_or_default();
        let qualities = db.get_all_qualities().unwrap_or_default();
        let quality_map: std::collections::HashMap<String, ProxyQuality> = qualities
            .into_iter()
            .map(|q| (q.proxy_id.clone(), q))
            .collect();

        for row in rows {
            let quality = quality_map.get(&row.id).map(|q| ProxyQualityInfo::from(q.clone()));
            let outbound: serde_json::Value =
                serde_json::from_str(&row.config_json).unwrap_or_default();
            // Derive tri-state: never validated → Untested, validated ok → Valid, validated fail → Invalid
            let status = if row.is_valid {
                ProxyStatus::Valid
            } else if row.last_validated.is_some() {
                ProxyStatus::Invalid
            } else {
                ProxyStatus::Untested
            };
            let proxy = PoolProxy {
                id: row.id.clone(),
                subscription_id: row.subscription_id,
                name: row.name,
                proxy_type: row.proxy_type,
                server: row.server,
                port: row.port as u16,
                singbox_outbound: outbound,
                status,
                local_port: row.local_port.map(|p| p as u16),
                error_count: row.error_count as u32,
                quality,
            };
            self.proxies.insert(row.id, proxy);
        }
        tracing::info!("Loaded {} proxies into pool", self.proxies.len());
    }

    pub fn add(&self, proxy: PoolProxy) {
        self.proxies.insert(proxy.id.clone(), proxy);
    }

    pub fn remove(&self, id: &str) {
        self.proxies.remove(id);
    }

    pub fn get(&self, id: &str) -> Option<PoolProxy> {
        self.proxies.get(id).map(|p| p.clone())
    }

    pub fn get_all(&self) -> Vec<PoolProxy> {
        self.proxies.iter().map(|p| p.value().clone()).collect()
    }

    pub fn get_valid_proxies(&self) -> Vec<PoolProxy> {
        self.proxies
            .iter()
            .filter(|p| p.status == ProxyStatus::Valid)
            .map(|p| p.value().clone())
            .collect()
    }

    pub fn set_status(&self, id: &str, status: ProxyStatus) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.status = status;
            match status {
                ProxyStatus::Valid => proxy.error_count = 0,
                ProxyStatus::Invalid => proxy.error_count += 1,
                ProxyStatus::Untested => {}
            }
        }
    }

    pub fn set_local_port(&self, id: &str, port: u16) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.local_port = Some(port);
        }
    }

    pub fn clear_local_port(&self, id: &str) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.local_port = None;
        }
    }

    pub fn clear_all_local_ports(&self) {
        for mut proxy in self.proxies.iter_mut() {
            proxy.local_port = None;
        }
    }

    pub fn set_quality(&self, id: &str, quality: ProxyQualityInfo) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.quality = Some(quality);
        }
    }

    pub fn count(&self) -> usize {
        self.proxies.len()
    }

    pub fn count_valid(&self) -> usize {
        self.proxies.iter().filter(|p| p.status == ProxyStatus::Valid).count()
    }

    pub fn remove_by_subscription(&self, sub_id: &str) {
        let ids: Vec<String> = self
            .proxies
            .iter()
            .filter(|p| p.subscription_id == sub_id)
            .map(|p| p.id.clone())
            .collect();
        for id in ids {
            self.proxies.remove(&id);
        }
    }

    pub fn update_proxy_config(&self, id: &str, name: &str, singbox_outbound: serde_json::Value) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.name = name.to_string();
            proxy.singbox_outbound = singbox_outbound;
        }
    }

    pub fn increment_error(&self, id: &str) {
        if let Some(mut proxy) = self.proxies.get_mut(id) {
            proxy.error_count += 1;
        }
    }

    pub fn filter_proxies(&self, filter: &ProxyFilter) -> Vec<PoolProxy> {
        let candidates: Vec<PoolProxy> = self
            .proxies
            .iter()
            .filter(|p| p.status == ProxyStatus::Valid && p.local_port.is_some())
            .filter(|p| {
                if let Some(ref proxy_type) = filter.proxy_type {
                    p.proxy_type == *proxy_type
                } else {
                    true
                }
            })
            .filter(|p| {
                if filter.chatgpt {
                    p.quality.as_ref().map(|q| q.chatgpt_accessible).unwrap_or(false)
                } else {
                    true
                }
            })
            .filter(|p| {
                if filter.google {
                    p.quality.as_ref().map(|q| q.google_accessible).unwrap_or(false)
                } else {
                    true
                }
            })
            .filter(|p| {
                if filter.residential {
                    p.quality.as_ref().map(|q| q.is_residential).unwrap_or(false)
                } else {
                    true
                }
            })
            .filter(|p| {
                if let Some(max) = filter.risk_max {
                    p.quality.as_ref().map(|q| q.risk_score <= max).unwrap_or(false)
                } else {
                    true
                }
            })
            .filter(|p| {
                if let Some(ref country) = filter.country {
                    p.quality
                        .as_ref()
                        .and_then(|q| q.country.as_ref())
                        .map(|c| c.eq_ignore_ascii_case(country))
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .map(|p| p.value().clone())
            .collect();

        candidates
    }

    pub fn pick_random(&self, filter: &ProxyFilter, count: usize) -> Vec<PoolProxy> {
        let mut candidates = self.filter_proxies(filter);
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(count);
        candidates
    }
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ProxyFilter {
    #[serde(default)]
    pub chatgpt: bool,
    #[serde(default)]
    pub google: bool,
    #[serde(default)]
    pub residential: bool,
    pub risk_max: Option<f64>,
    pub country: Option<String>,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
    pub count: Option<usize>,
    pub proxy_id: Option<String>,
}
