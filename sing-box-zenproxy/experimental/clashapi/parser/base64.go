package parser

import "strings"

func ParseBase64(content string) []ProxyConfig {
	trimmed := strings.TrimSpace(content)

	decoded := tryBase64Decode(trimmed)
	var text string
	if decoded != nil {
		text = string(decoded)
	} else {
		text = trimmed
	}

	return ParseV2Ray(text)
}
