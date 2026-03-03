use super::{ProxyConfig, ProxyType};
use serde_json::json;

pub fn parse(content: &str) -> Vec<ProxyConfig> {
    let yaml: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse Clash YAML: {e}");
            return vec![];
        }
    };

    let proxies = yaml.get("proxies").and_then(|p| p.as_sequence());
    let proxies = match proxies {
        Some(p) => p,
        None => return vec![],
    };

    proxies
        .iter()
        .filter_map(|proxy| parse_clash_proxy(proxy))
        .collect()
}

fn parse_clash_proxy(proxy: &serde_yaml::Value) -> Option<ProxyConfig> {
    let proxy_type = proxy.get("type")?.as_str()?;
    let server = proxy.get("server")?.as_str()?.to_string();
    let port = proxy.get("port")?.as_u64()? as u16;
    let name = proxy
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(&format!("{server}:{port}"))
        .to_string();

    match proxy_type {
        "vmess" => parse_clash_vmess(proxy, &name, &server, port),
        "vless" => parse_clash_vless(proxy, &name, &server, port),
        "trojan" => parse_clash_trojan(proxy, &name, &server, port),
        "ss" => parse_clash_ss(proxy, &name, &server, port),
        "hysteria2" | "hy2" => parse_clash_hysteria2(proxy, &name, &server, port),
        "socks5" => parse_clash_socks(proxy, &name, &server, port),
        "http" => parse_clash_http(proxy, &name, &server, port),
        _ => None,
    }
}

fn parse_clash_vmess(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let uuid = proxy.get("uuid")?.as_str()?;
    let alter_id = proxy
        .get("alterId")
        .and_then(|a| a.as_u64())
        .unwrap_or(0);
    let cipher = proxy
        .get("cipher")
        .and_then(|c| c.as_str())
        .unwrap_or("auto");

    let mut outbound = json!({
        "type": "vmess",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "alter_id": alter_id,
        "security": cipher,
    });

    apply_clash_transport(proxy, &mut outbound, server);
    apply_clash_tls(proxy, &mut outbound, server);

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::VMess,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_vless(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let uuid = proxy.get("uuid")?.as_str()?;

    let mut outbound = json!({
        "type": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    });

    if let Some(flow) = proxy.get("flow").and_then(|f| f.as_str()) {
        if !flow.is_empty() {
            outbound["flow"] = json!(flow);
        }
    }

    apply_clash_transport(proxy, &mut outbound, server);
    apply_clash_tls(proxy, &mut outbound, server);

    // Reality
    if let Some(reality_opts) = proxy.get("reality-opts") {
        if let Some(tls) = outbound.get_mut("tls") {
            let pbk = reality_opts
                .get("public-key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sid = reality_opts
                .get("short-id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            tls["reality"] = json!({
                "enabled": true,
                "public_key": pbk,
                "short_id": sid,
            });
        }
    }

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::VLESS,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_trojan(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let password = proxy.get("password")?.as_str()?;
    let sni = proxy
        .get("sni")
        .and_then(|s| s.as_str())
        .unwrap_or(server);

    let mut outbound = json!({
        "type": "trojan",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": true,
            "server_name": sni,
            "insecure": true,
        }
    });

    apply_clash_transport(proxy, &mut outbound, server);

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::Trojan,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_ss(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let cipher = proxy.get("cipher")?.as_str()?;
    let password = proxy.get("password")?.as_str()?;

    let outbound = json!({
        "type": "shadowsocks",
        "server": server,
        "server_port": port,
        "method": cipher,
        "password": password,
    });

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::Shadowsocks,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_hysteria2(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let password = proxy.get("password")?.as_str()?;
    let sni = proxy
        .get("sni")
        .and_then(|s| s.as_str())
        .unwrap_or(server);

    let mut outbound = json!({
        "type": "hysteria2",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": true,
            "server_name": sni,
            "insecure": true,
        }
    });

    if let Some(obfs) = proxy.get("obfs").and_then(|o| o.as_str()) {
        let obfs_password = proxy
            .get("obfs-password")
            .and_then(|o| o.as_str())
            .unwrap_or("");
        if obfs == "salamander" {
            outbound["obfs"] = json!({
                "type": "salamander",
                "password": obfs_password,
            });
        }
    }

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::Hysteria2,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_socks(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let mut outbound = json!({
        "type": "socks",
        "server": server,
        "server_port": port,
        "version": "5",
    });

    if let Some(username) = proxy.get("username").and_then(|u| u.as_str()) {
        if !username.is_empty() {
            outbound["username"] = json!(username);
            let password = proxy
                .get("password")
                .and_then(|p| p.as_str())
                .unwrap_or("");
            outbound["password"] = json!(password);
        }
    }

    // Some Clash configs use "tls" field for socks5
    let tls_enabled = proxy
        .get("tls")
        .and_then(|t| t.as_bool())
        .unwrap_or(false);
    if tls_enabled {
        apply_clash_tls(proxy, &mut outbound, server);
    }

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::Socks,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_clash_http(
    proxy: &serde_yaml::Value,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyConfig> {
    let mut outbound = json!({
        "type": "http",
        "server": server,
        "server_port": port,
    });

    if let Some(username) = proxy.get("username").and_then(|u| u.as_str()) {
        if !username.is_empty() {
            outbound["username"] = json!(username);
            let password = proxy
                .get("password")
                .and_then(|p| p.as_str())
                .unwrap_or("");
            outbound["password"] = json!(password);
        }
    }

    let tls_enabled = proxy
        .get("tls")
        .and_then(|t| t.as_bool())
        .unwrap_or(false);
    if tls_enabled {
        apply_clash_tls(proxy, &mut outbound, server);
    }

    Some(ProxyConfig {
        name: name.to_string(),
        proxy_type: ProxyType::Http,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn apply_clash_transport(
    proxy: &serde_yaml::Value,
    outbound: &mut serde_json::Value,
    _server: &str,
) {
    let network = proxy
        .get("network")
        .and_then(|n| n.as_str())
        .unwrap_or("tcp");
    match network {
        "ws" => {
            let path = proxy
                .get("ws-opts")
                .and_then(|o| o.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("/");
            let host = proxy
                .get("ws-opts")
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|h| h.as_str())
                .unwrap_or("");
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": { "Host": host }
            });
        }
        "grpc" => {
            let service_name = proxy
                .get("grpc-opts")
                .and_then(|o| o.get("grpc-service-name"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": service_name
            });
        }
        "h2" => {
            let path = proxy
                .get("h2-opts")
                .and_then(|o| o.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("/");
            let host = proxy
                .get("h2-opts")
                .and_then(|o| o.get("host"))
                .and_then(|h| h.as_sequence())
                .and_then(|arr| arr.first())
                .and_then(|h| h.as_str())
                .unwrap_or("");
            outbound["transport"] = json!({
                "type": "http",
                "host": [host],
                "path": path
            });
        }
        _ => {}
    }
}

fn apply_clash_tls(
    proxy: &serde_yaml::Value,
    outbound: &mut serde_json::Value,
    server: &str,
) {
    let tls_enabled = proxy
        .get("tls")
        .and_then(|t| t.as_bool())
        .unwrap_or(false);
    if tls_enabled {
        let sni = proxy
            .get("servername")
            .or_else(|| proxy.get("sni"))
            .and_then(|s| s.as_str())
            .unwrap_or(server);
        let skip_verify = proxy
            .get("skip-cert-verify")
            .and_then(|s| s.as_bool())
            .unwrap_or(true);
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": sni,
            "insecure": skip_verify,
        });

        // UTLS fingerprint
        if let Some(fp) = proxy.get("client-fingerprint").and_then(|f| f.as_str()) {
            outbound["tls"]["utls"] = json!({
                "enabled": true,
                "fingerprint": fp
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sc0() {
        let content = std::fs::read_to_string("C:/tmp/sc0.yaml").unwrap();
        let result = parse(&content);
        println!("Parsed {} proxies", result.len());
        for p in &result {
            println!("  {} | {} | {}:{}", p.name, p.proxy_type, p.server, p.port);
        }
        assert!(result.len() > 0, "Should parse some proxies");
    }
}
