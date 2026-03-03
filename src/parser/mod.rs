pub mod v2ray;
pub mod clash;
pub mod base64;
pub mod plain;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    VMess,
    VLESS,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Socks,
    Http,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::VMess => write!(f, "vmess"),
            ProxyType::VLESS => write!(f, "vless"),
            ProxyType::Trojan => write!(f, "trojan"),
            ProxyType::Shadowsocks => write!(f, "shadowsocks"),
            ProxyType::Hysteria2 => write!(f, "hysteria2"),
            ProxyType::Socks => write!(f, "socks"),
            ProxyType::Http => write!(f, "http"),
        }
    }
}

impl ProxyType {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "vmess" => Some(ProxyType::VMess),
            "vless" => Some(ProxyType::VLESS),
            "trojan" => Some(ProxyType::Trojan),
            "ss" | "shadowsocks" => Some(ProxyType::Shadowsocks),
            "hy2" | "hysteria2" | "hysteria" => Some(ProxyType::Hysteria2),
            "socks" | "socks5" | "socks4" => Some(ProxyType::Socks),
            "http" | "https" => Some(ProxyType::Http),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub name: String,
    pub proxy_type: ProxyType,
    pub server: String,
    pub port: u16,
    pub singbox_outbound: serde_json::Value,
}

pub fn parse_subscription(content: &str, sub_type: &str) -> Vec<ProxyConfig> {
    match sub_type {
        "auto" => parse_subscription_auto(content),
        "v2ray" => v2ray::parse(content),
        "clash" => clash::parse(content),
        "base64" => base64::parse(content),
        "socks5" | "socks4" | "http" | "https" => plain::parse(content, sub_type),
        _ => {
            tracing::warn!("Unknown subscription type: {sub_type}, falling back to auto-detect");
            parse_subscription_auto(content)
        }
    }
}

pub fn parse_subscription_auto(content: &str) -> Vec<ProxyConfig> {
    // Try clash first (cheapest check: YAML with `proxies:` key)
    let clash_result = clash::parse(content);
    if !clash_result.is_empty() {
        tracing::info!("Auto-detect: parsed {} proxies as Clash YAML", clash_result.len());
        return clash_result;
    }

    // Try base64 (base64 decode → v2ray URIs)
    let base64_result = base64::parse(content);
    if !base64_result.is_empty() {
        tracing::info!("Auto-detect: parsed {} proxies as Base64", base64_result.len());
        return base64_result;
    }

    // Try v2ray (raw lines with protocol URIs)
    let v2ray_result = v2ray::parse(content);
    if !v2ray_result.is_empty() {
        tracing::info!("Auto-detect: parsed {} proxies as V2Ray URIs", v2ray_result.len());
        return v2ray_result;
    }

    tracing::warn!("Auto-detect: no proxies found with any parser");
    vec![]
}
