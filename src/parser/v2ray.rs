use super::{ProxyConfig, ProxyType};
use base64::Engine;
use serde_json::json;

pub fn parse(content: &str) -> Vec<ProxyConfig> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| parse_uri(line.trim()))
        .collect()
}

pub fn parse_uri(uri: &str) -> Option<ProxyConfig> {
    if uri.starts_with("vmess://") {
        parse_vmess(uri)
    } else if uri.starts_with("vless://") {
        parse_vless(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan(uri)
    } else if uri.starts_with("ss://") {
        parse_ss(uri)
    } else if uri.starts_with("hy2://") || uri.starts_with("hysteria2://") {
        parse_hysteria2(uri)
    } else if uri.starts_with("socks://") || uri.starts_with("socks5://") || uri.starts_with("socks4://") {
        parse_socks(uri)
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        parse_http_proxy(uri)
    } else {
        None
    }
}

fn parse_vmess(uri: &str) -> Option<ProxyConfig> {
    let encoded = uri.strip_prefix("vmess://")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.trim()))
        .ok()?;
    let json_str = String::from_utf8(decoded).ok()?;
    let v: serde_json::Value = serde_json::from_str(&json_str).ok()?;

    let server = v["add"].as_str().unwrap_or("").to_string();
    let port = v["port"].as_u64()
        .or_else(|| v["port"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0) as u16;
    let uuid = v["id"].as_str().unwrap_or("").to_string();
    let alter_id = v["aid"].as_u64()
        .or_else(|| v["aid"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0);
    let name = v["ps"].as_str().unwrap_or(&format!("{server}:{port}")).to_string();
    let net = v["net"].as_str().unwrap_or("tcp");
    let tls = v["tls"].as_str().unwrap_or("");
    let sni = v["sni"].as_str().or_else(|| v["host"].as_str()).unwrap_or("");
    let host = v["host"].as_str().unwrap_or("");
    let path = v["path"].as_str().unwrap_or("");

    if server.is_empty() || port == 0 {
        return None;
    }

    let mut outbound = json!({
        "type": "vmess",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "alter_id": alter_id,
        "security": v["scy"].as_str().unwrap_or("auto"),
    });

    // Transport
    match net {
        "ws" => {
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": { "Host": host }
            });
        }
        "grpc" => {
            let service_name = v["path"].as_str().unwrap_or("");
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": service_name
            });
        }
        "h2" | "http" => {
            outbound["transport"] = json!({
                "type": "http",
                "host": [host],
                "path": path
            });
        }
        _ => {}
    }

    // TLS
    if tls == "tls" {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": if sni.is_empty() { &server } else { sni },
            "insecure": true
        });
    }

    Some(ProxyConfig {
        name,
        proxy_type: ProxyType::VMess,
        server: server.clone(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_vless(uri: &str) -> Option<ProxyConfig> {
    let without_scheme = uri.strip_prefix("vless://")?;
    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    let (userinfo, host_and_params) = main_part.split_once('@')?;
    let uuid = userinfo.to_string();

    let (host_port, query) = host_and_params.split_once('?').unwrap_or((host_and_params, ""));
    let (server, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse().ok()?;
    let params = parse_query(query);

    let security = params.get("security").map(|s| s.as_str()).unwrap_or("");
    let transport_type = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let sni = params.get("sni").map(|s| s.as_str()).unwrap_or("");
    let flow = params.get("flow").map(|s| s.as_str()).unwrap_or("");
    let host = params.get("host").map(|s| s.as_str()).unwrap_or("");
    let path = params.get("path").map(|s| s.as_str()).unwrap_or("");

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let mut outbound = json!({
        "type": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    });

    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }

    // Transport
    apply_transport(&mut outbound, transport_type, host, path, &params);

    // TLS
    if security == "tls" || security == "reality" {
        let mut tls = json!({
            "enabled": true,
            "server_name": if sni.is_empty() { &server } else { sni },
            "insecure": true,
        });
        if security == "reality" {
            let pbk = params.get("pbk").map(|s| s.as_str()).unwrap_or("");
            let sid = params.get("sid").map(|s| s.as_str()).unwrap_or("");
            let fp = params.get("fp").map(|s| s.as_str()).unwrap_or("chrome");
            tls["reality"] = json!({
                "enabled": true,
                "public_key": pbk,
                "short_id": sid,
            });
            tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
        }
        outbound["tls"] = tls;
    }

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::VLESS,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_trojan(uri: &str) -> Option<ProxyConfig> {
    let without_scheme = uri.strip_prefix("trojan://")?;
    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    let (password, host_and_params) = main_part.split_once('@')?;
    let (host_port, query) = host_and_params.split_once('?').unwrap_or((host_and_params, ""));
    let (server, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse().ok()?;
    let params = parse_query(query);

    let sni = params.get("sni").map(|s| s.as_str()).unwrap_or("");
    let transport_type = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let host = params.get("host").map(|s| s.as_str()).unwrap_or("");
    let path = params.get("path").map(|s| s.as_str()).unwrap_or("");

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let mut outbound = json!({
        "type": "trojan",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": true,
            "server_name": if sni.is_empty() { &server } else { sni },
            "insecure": true,
        }
    });

    apply_transport(&mut outbound, transport_type, host, path, &params);

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::Trojan,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_ss(uri: &str) -> Option<ProxyConfig> {
    let without_scheme = uri.strip_prefix("ss://")?;
    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    // Try SIP002 format: ss://base64(method:password)@host:port
    // or legacy: ss://base64(method:password@host:port)
    let (method, password, server, port) = if main_part.contains('@') {
        let (encoded, host_port) = main_part.split_once('@')?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
            .ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (method, password) = decoded_str.split_once(':')?;

        let host_port_clean = host_port.split('?').next().unwrap_or(host_port);
        let (server, port_str) = parse_host_port(host_port_clean)?;
        let port: u16 = port_str.parse().ok()?;
        (method.to_string(), password.to_string(), server.to_string(), port)
    } else {
        // Legacy format
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(main_part)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(main_part))
            .ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (method_pass, host_port) = decoded_str.rsplit_once('@')?;
        let (method, password) = method_pass.split_once(':')?;
        let (server, port_str) = parse_host_port(host_port)?;
        let port: u16 = port_str.parse().ok()?;
        (method.to_string(), password.to_string(), server.to_string(), port)
    };

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let outbound = json!({
        "type": "shadowsocks",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
    });

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::Shadowsocks,
        server,
        port,
        singbox_outbound: outbound,
    })
}

fn parse_hysteria2(uri: &str) -> Option<ProxyConfig> {
    let without_scheme = uri
        .strip_prefix("hy2://")
        .or_else(|| uri.strip_prefix("hysteria2://"))?;
    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    let (password, host_and_params) = main_part.split_once('@')?;
    let (host_port, query) = host_and_params.split_once('?').unwrap_or((host_and_params, ""));
    let (server, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse().ok()?;
    let params = parse_query(query);

    let sni = params.get("sni").map(|s| s.as_str()).unwrap_or("");
    let obfs = params.get("obfs").map(|s| s.as_str()).unwrap_or("");
    let obfs_password = params.get("obfs-password").map(|s| s.as_str()).unwrap_or("");

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let mut outbound = json!({
        "type": "hysteria2",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": true,
            "server_name": if sni.is_empty() { &server } else { sni },
            "insecure": true,
        }
    });

    if obfs == "salamander" && !obfs_password.is_empty() {
        outbound["obfs"] = json!({
            "type": "salamander",
            "password": obfs_password,
        });
    }

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::Hysteria2,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_socks(uri: &str) -> Option<ProxyConfig> {
    // Determine SOCKS version from scheme
    let (without_scheme, version) = if uri.starts_with("socks4://") {
        (uri.strip_prefix("socks4://")?, "4a")
    } else if uri.starts_with("socks5://") {
        (uri.strip_prefix("socks5://")?, "5")
    } else {
        (uri.strip_prefix("socks://")?, "5")
    };

    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    let (username, password, host_port) = if main_part.contains('@') {
        let (userinfo, hp) = main_part.split_once('@')?;
        if let Some((user, pass)) = userinfo.split_once(':') {
            (user.to_string(), pass.to_string(), hp)
        } else {
            (userinfo.to_string(), String::new(), hp)
        }
    } else {
        (String::new(), String::new(), main_part)
    };

    let (server, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse().ok()?;

    if server.is_empty() || port == 0 {
        return None;
    }

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let mut outbound = json!({
        "type": "socks",
        "server": server,
        "server_port": port,
        "version": version,
    });

    if !username.is_empty() {
        outbound["username"] = json!(username);
        outbound["password"] = json!(password);
    }

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::Socks,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

fn parse_http_proxy(uri: &str) -> Option<ProxyConfig> {
    let is_https = uri.starts_with("https://");
    let without_scheme = if is_https {
        uri.strip_prefix("https://")?
    } else {
        uri.strip_prefix("http://")?
    };

    let (main_part, fragment) = without_scheme.rsplit_once('#').unwrap_or((without_scheme, ""));
    let name = percent_encoding::percent_decode_str(fragment)
        .decode_utf8_lossy()
        .to_string();

    // Remove path component (e.g. trailing /)
    let main_part = main_part.split('/').next().unwrap_or(main_part);

    let (username, password, host_port) = if main_part.contains('@') {
        let (userinfo, hp) = main_part.split_once('@')?;
        if let Some((user, pass)) = userinfo.split_once(':') {
            (user.to_string(), pass.to_string(), hp)
        } else {
            (userinfo.to_string(), String::new(), hp)
        }
    } else {
        (String::new(), String::new(), main_part)
    };

    let (server, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse().ok()?;

    if server.is_empty() || port == 0 {
        return None;
    }

    let display_name = if name.is_empty() { format!("{server}:{port}") } else { name };

    let mut outbound = json!({
        "type": "http",
        "server": server,
        "server_port": port,
    });

    if !username.is_empty() {
        outbound["username"] = json!(username);
        outbound["password"] = json!(password);
    }

    if is_https {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": server,
            "insecure": true,
        });
    }

    Some(ProxyConfig {
        name: display_name,
        proxy_type: ProxyType::Http,
        server: server.to_string(),
        port,
        singbox_outbound: outbound,
    })
}

// --- Helpers ---

fn parse_host_port(s: &str) -> Option<(&str, &str)> {
    // Handle IPv6: [::1]:port
    if s.starts_with('[') {
        let end_bracket = s.find(']')?;
        let host = &s[1..end_bracket];
        let port = s[end_bracket + 1..].strip_prefix(':')?;
        Some((host, port))
    } else {
        s.rsplit_once(':')
    }
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if query.is_empty() {
        return map;
    }
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let decoded = percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .to_string();
            map.insert(k.to_string(), decoded);
        }
    }
    map
}

fn apply_transport(
    outbound: &mut serde_json::Value,
    transport_type: &str,
    host: &str,
    path: &str,
    params: &std::collections::HashMap<String, String>,
) {
    match transport_type {
        "ws" => {
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": { "Host": host }
            });
        }
        "grpc" => {
            let service_name = params.get("serviceName").map(|s| s.as_str()).unwrap_or(path);
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": service_name
            });
        }
        "h2" | "http" => {
            outbound["transport"] = json!({
                "type": "http",
                "host": [host],
                "path": path
            });
        }
        _ => {}
    }
}
