package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func ParseV2Ray(content string) []ProxyConfig {
	var results []ProxyConfig
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pc := parseV2RayURI(line); pc != nil {
			results = append(results, *pc)
		}
	}
	return results
}

func parseV2RayURI(uri string) *ProxyConfig {
	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return parseVMess(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseVLess(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojan(uri)
	case strings.HasPrefix(uri, "ss://"):
		return parseSS(uri)
	case strings.HasPrefix(uri, "hy2://"), strings.HasPrefix(uri, "hysteria2://"):
		return parseHysteria2(uri)
	case strings.HasPrefix(uri, "socks://"), strings.HasPrefix(uri, "socks5://"), strings.HasPrefix(uri, "socks4://"):
		return parseSocks(uri)
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		return parseHTTPProxy(uri)
	}
	return nil
}

func parseVMess(uri string) *ProxyConfig {
	encoded := strings.TrimPrefix(uri, "vmess://")
	encoded = strings.TrimSpace(encoded)

	decoded := tryBase64Decode(encoded)
	if decoded == nil {
		return nil
	}

	var v map[string]interface{}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil
	}

	server := jsonStr(v, "add")
	port := jsonPort(v, "port")
	uuid := jsonStr(v, "id")
	alterID := jsonInt(v, "aid")
	name := jsonStr(v, "ps")
	net := jsonStrDefault(v, "net", "tcp")
	tls := jsonStr(v, "tls")
	sni := jsonStr(v, "sni")
	if sni == "" {
		sni = jsonStr(v, "host")
	}
	host := jsonStr(v, "host")
	path := jsonStr(v, "path")
	security := jsonStrDefault(v, "scy", "auto")

	if server == "" || port == 0 {
		return nil
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	outbound := map[string]interface{}{
		"type":        "vmess",
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"alter_id":    alterID,
		"security":    security,
	}

	switch net {
	case "ws":
		outbound["transport"] = map[string]interface{}{
			"type":    "ws",
			"path":    path,
			"headers": map[string]interface{}{"Host": host},
		}
	case "grpc":
		outbound["transport"] = map[string]interface{}{
			"type":         "grpc",
			"service_name": path,
		}
	case "h2", "http":
		outbound["transport"] = map[string]interface{}{
			"type": "http",
			"host": []string{host},
			"path": path,
		}
	}

	if tls == "tls" {
		serverName := sni
		if serverName == "" {
			serverName = server
		}
		outbound["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    true,
		}
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "vmess",
		Server:   server,
		Port:     port,
		Outbound: raw,
	}
}

func parseVLess(uri string) *ProxyConfig {
	without := strings.TrimPrefix(uri, "vless://")
	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	atIdx := strings.Index(mainPart, "@")
	if atIdx < 0 {
		return nil
	}
	uuid := mainPart[:atIdx]
	hostAndParams := mainPart[atIdx+1:]

	hostPort, query := splitQuery(hostAndParams)
	server, portStr := parseHostPort(hostPort)
	if server == "" {
		return nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}
	params := parseQueryParams(query)

	security := params["security"]
	transportType := params["type"]
	if transportType == "" {
		transportType = "tcp"
	}
	sni := params["sni"]
	flow := params["flow"]
	host := params["host"]
	path := urlDecode(params["path"])

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	outbound := map[string]interface{}{
		"type":        "vless",
		"server":      server,
		"server_port": uint16(port),
		"uuid":        uuid,
	}
	if flow != "" {
		outbound["flow"] = flow
	}

	applyTransport(outbound, transportType, host, path, params)

	if security == "tls" || security == "reality" {
		serverName := sni
		if serverName == "" {
			serverName = server
		}
		tlsConfig := map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    true,
		}
		if security == "reality" {
			pbk := params["pbk"]
			sid := params["sid"]
			fp := params["fp"]
			if fp == "" {
				fp = "chrome"
			}
			tlsConfig["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": pbk,
				"short_id":   sid,
			}
			tlsConfig["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			}
		}
		outbound["tls"] = tlsConfig
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "vless",
		Server:   server,
		Port:     uint16(port),
		Outbound: raw,
	}
}

func parseTrojan(uri string) *ProxyConfig {
	without := strings.TrimPrefix(uri, "trojan://")
	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	atIdx := strings.Index(mainPart, "@")
	if atIdx < 0 {
		return nil
	}
	password := mainPart[:atIdx]
	hostAndParams := mainPart[atIdx+1:]

	hostPort, query := splitQuery(hostAndParams)
	server, portStr := parseHostPort(hostPort)
	if server == "" {
		return nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}
	params := parseQueryParams(query)

	sni := params["sni"]
	transportType := params["type"]
	if transportType == "" {
		transportType = "tcp"
	}
	host := params["host"]
	path := urlDecode(params["path"])

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	serverName := sni
	if serverName == "" {
		serverName = server
	}

	outbound := map[string]interface{}{
		"type":        "trojan",
		"server":      server,
		"server_port": uint16(port),
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    true,
		},
	}

	applyTransport(outbound, transportType, host, path, params)

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "trojan",
		Server:   server,
		Port:     uint16(port),
		Outbound: raw,
	}
}

func parseSS(uri string) *ProxyConfig {
	without := strings.TrimPrefix(uri, "ss://")
	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	var method, password, server string
	var port uint16

	if strings.Contains(mainPart, "@") {
		// SIP002: ss://base64(method:password)@host:port
		atIdx := strings.Index(mainPart, "@")
		encoded := mainPart[:atIdx]
		hostPortPart := mainPart[atIdx+1:]

		decoded := tryBase64Decode(encoded)
		if decoded == nil {
			return nil
		}
		decodedStr := string(decoded)
		colonIdx := strings.Index(decodedStr, ":")
		if colonIdx < 0 {
			return nil
		}
		method = decodedStr[:colonIdx]
		password = decodedStr[colonIdx+1:]

		// Remove query params from host:port
		hostPortClean := strings.SplitN(hostPortPart, "?", 2)[0]
		server, portStr := parseHostPort(hostPortClean)
		if server == "" {
			return nil
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil
		}
		port = uint16(p)
	} else {
		// Legacy: ss://base64(method:password@host:port)
		decoded := tryBase64Decode(mainPart)
		if decoded == nil {
			return nil
		}
		decodedStr := string(decoded)
		atIdx := strings.LastIndex(decodedStr, "@")
		if atIdx < 0 {
			return nil
		}
		methodPass := decodedStr[:atIdx]
		hostPortPart := decodedStr[atIdx+1:]

		colonIdx := strings.Index(methodPass, ":")
		if colonIdx < 0 {
			return nil
		}
		method = methodPass[:colonIdx]
		password = methodPass[colonIdx+1:]

		server, portStr := parseHostPort(hostPortPart)
		if server == "" {
			return nil
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil
		}
		port = uint16(p)
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    password,
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "shadowsocks",
		Server:   server,
		Port:     port,
		Outbound: raw,
	}
}

func parseHysteria2(uri string) *ProxyConfig {
	without := strings.TrimPrefix(uri, "hysteria2://")
	without = strings.TrimPrefix(without, "hy2://")
	// If original was hy2://, the first TrimPrefix is a no-op
	if strings.HasPrefix(uri, "hy2://") {
		without = strings.TrimPrefix(uri, "hy2://")
	}

	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	atIdx := strings.Index(mainPart, "@")
	if atIdx < 0 {
		return nil
	}
	password := mainPart[:atIdx]
	hostAndParams := mainPart[atIdx+1:]

	hostPort, query := splitQuery(hostAndParams)
	server, portStr := parseHostPort(hostPort)
	if server == "" {
		return nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}
	params := parseQueryParams(query)

	sni := params["sni"]
	obfs := params["obfs"]
	obfsPassword := params["obfs-password"]

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	serverName := sni
	if serverName == "" {
		serverName = server
	}

	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"server":      server,
		"server_port": uint16(port),
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    true,
		},
	}

	if obfs == "salamander" && obfsPassword != "" {
		outbound["obfs"] = map[string]interface{}{
			"type":     "salamander",
			"password": obfsPassword,
		}
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "hysteria2",
		Server:   server,
		Port:     uint16(port),
		Outbound: raw,
	}
}

func parseSocks(uri string) *ProxyConfig {
	// Determine version from scheme
	version := "5"
	var without string
	switch {
	case strings.HasPrefix(uri, "socks4://"):
		without = strings.TrimPrefix(uri, "socks4://")
		version = "4a"
	case strings.HasPrefix(uri, "socks5://"):
		without = strings.TrimPrefix(uri, "socks5://")
	default:
		without = strings.TrimPrefix(uri, "socks://")
	}

	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	var username, password, hostPort string
	if atIdx := strings.Index(mainPart, "@"); atIdx >= 0 {
		userinfo := mainPart[:atIdx]
		hostPort = mainPart[atIdx+1:]
		if colonIdx := strings.Index(userinfo, ":"); colonIdx >= 0 {
			username = userinfo[:colonIdx]
			password = userinfo[colonIdx+1:]
		} else {
			username = userinfo
		}
	} else {
		hostPort = mainPart
	}

	server, portStr := parseHostPort(hostPort)
	if server == "" {
		return nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	outbound := map[string]interface{}{
		"type":        "socks",
		"server":      server,
		"server_port": uint16(port),
		"version":     version,
	}

	if username != "" {
		outbound["username"] = username
		outbound["password"] = password
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "socks",
		Server:   server,
		Port:     uint16(port),
		Outbound: raw,
	}
}

func parseHTTPProxy(uri string) *ProxyConfig {
	isHTTPS := strings.HasPrefix(uri, "https://")
	var without string
	if isHTTPS {
		without = strings.TrimPrefix(uri, "https://")
	} else {
		without = strings.TrimPrefix(uri, "http://")
	}

	mainPart, fragment := splitFragment(without)
	name := urlDecode(fragment)

	// Remove path component
	if slashIdx := strings.Index(mainPart, "/"); slashIdx >= 0 {
		mainPart = mainPart[:slashIdx]
	}

	var username, password, hostPort string
	if atIdx := strings.Index(mainPart, "@"); atIdx >= 0 {
		userinfo := mainPart[:atIdx]
		hostPort = mainPart[atIdx+1:]
		if colonIdx := strings.Index(userinfo, ":"); colonIdx >= 0 {
			username = userinfo[:colonIdx]
			password = userinfo[colonIdx+1:]
		} else {
			username = userinfo
		}
	} else {
		hostPort = mainPart
	}

	server, portStr := parseHostPort(hostPort)
	if server == "" {
		return nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	outbound := map[string]interface{}{
		"type":        "http",
		"server":      server,
		"server_port": uint16(port),
	}

	if username != "" {
		outbound["username"] = username
		outbound["password"] = password
	}

	if isHTTPS {
		outbound["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": server,
			"insecure":    true,
		}
	}

	raw, _ := json.Marshal(outbound)
	return &ProxyConfig{
		Name:     name,
		Type:     "http",
		Server:   server,
		Port:     uint16(port),
		Outbound: raw,
	}
}

// --- Helpers ---

func parseHostPort(s string) (string, string) {
	if strings.HasPrefix(s, "[") {
		endBracket := strings.Index(s, "]")
		if endBracket < 0 {
			return "", ""
		}
		host := s[1:endBracket]
		rest := s[endBracket+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", ""
		}
		return host, rest[1:]
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", ""
	}
	return s[:idx], s[idx+1:]
}

func parseQueryParams(query string) map[string]string {
	params := make(map[string]string)
	if query == "" {
		return params
	}
	for _, pair := range strings.Split(query, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			params[k] = urlDecode(v)
		}
	}
	return params
}

func splitFragment(s string) (string, string) {
	idx := strings.LastIndex(s, "#")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func splitQuery(s string) (string, string) {
	idx := strings.Index(s, "?")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func urlDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

func applyTransport(outbound map[string]interface{}, transportType, host, path string, params map[string]string) {
	switch transportType {
	case "ws":
		outbound["transport"] = map[string]interface{}{
			"type":    "ws",
			"path":    path,
			"headers": map[string]interface{}{"Host": host},
		}
	case "grpc":
		serviceName := params["serviceName"]
		if serviceName == "" {
			serviceName = path
		}
		outbound["transport"] = map[string]interface{}{
			"type":         "grpc",
			"service_name": serviceName,
		}
	case "h2", "http":
		outbound["transport"] = map[string]interface{}{
			"type": "http",
			"host": []string{host},
			"path": path,
		}
	}
}

func tryBase64Decode(s string) []byte {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded
		}
	}
	return nil
}

func jsonStr(v map[string]interface{}, key string) string {
	val, ok := v[key]
	if !ok || val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}

func jsonStrDefault(v map[string]interface{}, key, def string) string {
	s := jsonStr(v, key)
	if s == "" {
		return def
	}
	return s
}

func jsonPort(v map[string]interface{}, key string) uint16 {
	val, ok := v[key]
	if !ok || val == nil {
		return 0
	}
	switch n := val.(type) {
	case float64:
		return uint16(n)
	case string:
		p, _ := strconv.ParseUint(n, 10, 16)
		return uint16(p)
	}
	return 0
}

func jsonInt(v map[string]interface{}, key string) int {
	val, ok := v[key]
	if !ok || val == nil {
		return 0
	}
	switch n := val.(type) {
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}
