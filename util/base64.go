package util

import (
	"encoding/base64"
	"strings"
)

func Base64URLDecode(raw string) (decS string, err error) {

	raw = strings.ReplaceAll(raw, "+", "-")
	raw = strings.ReplaceAll(raw, "/", "_")
	raw = strings.ReplaceAll(raw, "=", "")

	bytes, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}

	decS = string(bytes)

	return
}
