use super::{ProxyConfig, ProxyType};
use serde_json::json;

/// Parse plain-text proxy lines with a given proxy type.
///
/// Supported line formats:
/// - `host:port`
/// - `host:port:user:pass`
/// - `user:pass@host:port`
///
/// Also accepts URI lines (socks5://, http://, etc.) and delegates them to v2ray parser.
pub fn parse(content: &str, proxy_type_str: &str) -> Vec<ProxyConfig> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let line = line.trim();
            // If the line looks like a URI, delegate to the v2ray parser
            if line.contains("://") {
                return super::v2ray::parse_uri(line);
            }
            parse_plain_line(line, proxy_type_str)
        })
        .collect()
}

fn parse_plain_line(line: &str, proxy_type_str: &str) -> Option<ProxyConfig> {
    let (server, port, username, password) = if line.contains('@') {
        // user:pass@host:port
        let (userinfo, host_port) = line.split_once('@')?;
        let (user, pass) = userinfo.split_once(':')?;
        let (host, port_str) = host_port.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        (host.to_string(), port, user.to_string(), pass.to_string())
    } else {
        // Count colons to distinguish host:port from host:port:user:pass
        let parts: Vec<&str> = line.rsplitn(3, ':').collect();
        // rsplitn(3, ':') on "host:port:user:pass" won't work well since we need to handle
        // the case where host could be IPv6. Let's use a simpler approach.
        let colon_count = line.chars().filter(|&c| c == ':').count();
        if colon_count >= 3 {
            // host:port:user:pass — split from the right
            let rpos1 = line.rfind(':')?;
            let pass = &line[rpos1 + 1..];
            let rest = &line[..rpos1];
            let rpos2 = rest.rfind(':')?;
            let user = &rest[rpos2 + 1..];
            let host_port = &rest[..rpos2];
            let rpos3 = host_port.rfind(':')?;
            let port_str = &host_port[rpos3 + 1..];
            let host = &host_port[..rpos3];
            let port: u16 = port_str.parse().ok()?;
            (host.to_string(), port, user.to_string(), pass.to_string())
        } else {
            // host:port
            let _ = parts;
            let rpos = line.rfind(':')?;
            let port_str = &line[rpos + 1..];
            let host = &line[..rpos];
            let port: u16 = port_str.parse().ok()?;
            (host.to_string(), port, String::new(), String::new())
        }
    };

    if server.is_empty() || port == 0 {
        return None;
    }

    let name = format!("{server}:{port}");

    match proxy_type_str {
        "socks4" => {
            let mut outbound = json!({
                "type": "socks",
                "server": server,
                "server_port": port,
                "version": "4a",
            });
            if !username.is_empty() {
                outbound["username"] = json!(username);
                outbound["password"] = json!(password);
            }
            Some(ProxyConfig {
                name,
                proxy_type: ProxyType::Socks,
                server,
                port,
                singbox_outbound: outbound,
            })
        }
        "socks5" => {
            let mut outbound = json!({
                "type": "socks",
                "server": server,
                "server_port": port,
                "version": "5",
            });
            if !username.is_empty() {
                outbound["username"] = json!(username);
                outbound["password"] = json!(password);
            }
            Some(ProxyConfig {
                name,
                proxy_type: ProxyType::Socks,
                server,
                port,
                singbox_outbound: outbound,
            })
        }
        "http" => {
            let mut outbound = json!({
                "type": "http",
                "server": server,
                "server_port": port,
            });
            if !username.is_empty() {
                outbound["username"] = json!(username);
                outbound["password"] = json!(password);
            }
            Some(ProxyConfig {
                name,
                proxy_type: ProxyType::Http,
                server,
                port,
                singbox_outbound: outbound,
            })
        }
        "https" => {
            let mut outbound = json!({
                "type": "http",
                "server": server,
                "server_port": port,
                "tls": {
                    "enabled": true,
                    "server_name": server,
                    "insecure": true,
                },
            });
            if !username.is_empty() {
                outbound["username"] = json!(username);
                outbound["password"] = json!(password);
            }
            Some(ProxyConfig {
                name,
                proxy_type: ProxyType::Http,
                server,
                port,
                singbox_outbound: outbound,
            })
        }
        _ => None,
    }
}
