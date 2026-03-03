package parser

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParseClash(content string) []ProxyConfig {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}

	proxiesRaw, ok := doc["proxies"]
	if !ok {
		return nil
	}
	proxies, ok := proxiesRaw.([]interface{})
	if !ok {
		return nil
	}

	var results []ProxyConfig
	for _, p := range proxies {
		proxy, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if pc := parseClashProxy(proxy); pc != nil {
			results = append(results, *pc)
		}
	}
	return results
}

func parseClashProxy(proxy map[string]interface{}) *ProxyConfig {
	proxyType := yamlStr(proxy, "type")
	server := yamlStr(proxy, "server")
	port := yamlPort(proxy, "port")
	name := yamlStr(proxy, "name")
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}
	if server == "" || port == 0 {
		return nil
	}

	switch proxyType {
	case "vmess":
		return parseClashVMess(proxy, name, server, port)
	case "vless":
		return parseClashVLess(proxy, name, server, port)
	case "trojan":
		return parseClashTrojan(proxy, name, server, port)
	case "ss":
		return parseClashSS(proxy, name, server, port)
	case "hysteria2", "hy2":
		return parseClashHysteria2(proxy, name, server, port)
	case "socks5":
		return parseClashSocks5(proxy, name, server, port)
	case "http":
		return parseClashHTTP(proxy, name, server, port)
	}
	return nil
}

func parseClashVMess(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	uuid := yamlStr(proxy, "uuid")
	if uuid == "" {
		return nil
	}
	alterID := yamlInt(proxy, "alterId")
	cipher := yamlStrDefault(proxy, "cipher", "auto")

	outbound := map[string]interface{}{
		"type":        "vmess",
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"alter_id":    alterID,
		"security":    cipher,
	}

	applyClashTransport(proxy, outbound)
	applyClashTLS(proxy, outbound, server)

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "vmess", Server: server, Port: port, Outbound: raw}
}

func parseClashVLess(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	uuid := yamlStr(proxy, "uuid")
	if uuid == "" {
		return nil
	}

	outbound := map[string]interface{}{
		"type":        "vless",
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
	}

	if flow := yamlStr(proxy, "flow"); flow != "" {
		outbound["flow"] = flow
	}

	applyClashTransport(proxy, outbound)
	applyClashTLS(proxy, outbound, server)

	// Reality
	if realityOpts, ok := proxy["reality-opts"].(map[string]interface{}); ok {
		if tlsMap, ok := outbound["tls"].(map[string]interface{}); ok {
			pbk := yamlStr(realityOpts, "public-key")
			sid := yamlStr(realityOpts, "short-id")
			tlsMap["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": pbk,
				"short_id":   sid,
			}
		}
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "vless", Server: server, Port: port, Outbound: raw}
}

func parseClashTrojan(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	password := yamlStr(proxy, "password")
	if password == "" {
		return nil
	}
	sni := yamlStrDefault(proxy, "sni", server)

	outbound := map[string]interface{}{
		"type":        "trojan",
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
		},
	}

	applyClashTransport(proxy, outbound)

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "trojan", Server: server, Port: port, Outbound: raw}
}

func parseClashSS(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	cipher := yamlStr(proxy, "cipher")
	password := yamlStr(proxy, "password")
	if cipher == "" || password == "" {
		return nil
	}

	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"server":      server,
		"server_port": port,
		"method":      cipher,
		"password":    password,
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "shadowsocks", Server: server, Port: port, Outbound: raw}
}

func parseClashHysteria2(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	password := yamlStr(proxy, "password")
	if password == "" {
		return nil
	}
	sni := yamlStrDefault(proxy, "sni", server)

	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
		},
	}

	if obfs := yamlStr(proxy, "obfs"); obfs == "salamander" {
		obfsPassword := yamlStr(proxy, "obfs-password")
		outbound["obfs"] = map[string]interface{}{
			"type":     "salamander",
			"password": obfsPassword,
		}
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "hysteria2", Server: server, Port: port, Outbound: raw}
}

func parseClashSocks5(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	outbound := map[string]interface{}{
		"type":        "socks",
		"server":      server,
		"server_port": port,
		"version":     "5",
	}

	if username := yamlStr(proxy, "username"); username != "" {
		outbound["username"] = username
		outbound["password"] = yamlStr(proxy, "password")
	}

	if yamlBool(proxy, "tls") {
		applyClashTLS(proxy, outbound, server)
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "socks", Server: server, Port: port, Outbound: raw}
}

func parseClashHTTP(proxy map[string]interface{}, name, server string, port uint16) *ProxyConfig {
	outbound := map[string]interface{}{
		"type":        "http",
		"server":      server,
		"server_port": port,
	}

	if username := yamlStr(proxy, "username"); username != "" {
		outbound["username"] = username
		outbound["password"] = yamlStr(proxy, "password")
	}

	if yamlBool(proxy, "tls") {
		applyClashTLS(proxy, outbound, server)
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{Name: name, Type: "http", Server: server, Port: port, Outbound: raw}
}

func applyClashTransport(proxy map[string]interface{}, outbound map[string]interface{}) {
	network := yamlStrDefault(proxy, "network", "tcp")
	switch network {
	case "ws":
		wsOpts, _ := proxy["ws-opts"].(map[string]interface{})
		path := "/"
		host := ""
		if wsOpts != nil {
			if p := yamlStr(wsOpts, "path"); p != "" {
				path = p
			}
			if headers, ok := wsOpts["headers"].(map[string]interface{}); ok {
				host = yamlStr(headers, "Host")
			}
		}
		outbound["transport"] = map[string]interface{}{
			"type":    "ws",
			"path":    path,
			"headers": map[string]interface{}{"Host": host},
		}
	case "grpc":
		grpcOpts, _ := proxy["grpc-opts"].(map[string]interface{})
		serviceName := ""
		if grpcOpts != nil {
			serviceName = yamlStr(grpcOpts, "grpc-service-name")
		}
		outbound["transport"] = map[string]interface{}{
			"type":         "grpc",
			"service_name": serviceName,
		}
	case "h2":
		h2Opts, _ := proxy["h2-opts"].(map[string]interface{})
		path := "/"
		host := ""
		if h2Opts != nil {
			if p := yamlStr(h2Opts, "path"); p != "" {
				path = p
			}
			if hostArr, ok := h2Opts["host"].([]interface{}); ok && len(hostArr) > 0 {
				if h, ok := hostArr[0].(string); ok {
					host = h
				}
			}
		}
		outbound["transport"] = map[string]interface{}{
			"type": "http",
			"host": []string{host},
			"path": path,
		}
	}
}

func applyClashTLS(proxy map[string]interface{}, outbound map[string]interface{}, server string) {
	tlsEnabled := yamlBool(proxy, "tls")
	if !tlsEnabled {
		return
	}

	sni := yamlStr(proxy, "servername")
	if sni == "" {
		sni = yamlStr(proxy, "sni")
	}
	if sni == "" {
		sni = server
	}
	skipVerify := true
	if v, ok := proxy["skip-cert-verify"]; ok {
		if b, ok := v.(bool); ok {
			skipVerify = b
		}
	}

	tlsConfig := map[string]interface{}{
		"enabled":     true,
		"server_name": sni,
		"insecure":    skipVerify,
	}

	if fp := yamlStr(proxy, "client-fingerprint"); fp != "" {
		tlsConfig["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	outbound["tls"] = tlsConfig
}

// --- YAML helpers ---

func yamlStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func yamlStrDefault(m map[string]interface{}, key, def string) string {
	s := yamlStr(m, key)
	if s == "" {
		return def
	}
	return s
}

func yamlPort(m map[string]interface{}, key string) uint16 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return uint16(n)
	case float64:
		return uint16(n)
	case string:
		p, _ := fmt.Sscanf(n, "%d")
		return uint16(p)
	}
	return 0
}

func yamlInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func yamlBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}
