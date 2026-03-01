package parser

import "encoding/json"

type ProxyConfig struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Server   string          `json:"server"`
	Port     uint16          `json:"port"`
	Outbound json.RawMessage `json:"outbound"`
}

func Parse(content, subType string) []ProxyConfig {
	switch subType {
	case "v2ray":
		return ParseV2Ray(content)
	case "clash":
		return ParseClash(content)
	case "base64":
		return ParseBase64(content)
	case "auto":
		return ParseAuto(content)
	default:
		return ParseAuto(content)
	}
}

func ParseAuto(content string) []ProxyConfig {
	if result := ParseClash(content); len(result) > 0 {
		return result
	}
	if result := ParseBase64(content); len(result) > 0 {
		return result
	}
	if result := ParseV2Ray(content); len(result) > 0 {
		return result
	}
	return nil
}

func ParseURI(uri string) *ProxyConfig {
	return parseV2RayURI(uri)
}
