package common

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func ParseKeyList(keys []string) ([]string, []string, error) {
	var valid []string
	var ignored []string

	for _, line := range keys {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(rest) > 0 {
			ignored = append(ignored, line)
			continue
		}
		key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
		valid = append(valid, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	}
	return valid, ignored, nil
}

func ParseKeys(content string) ([]string, []string, error) {
	lines := strings.Split(content, "\n")
	return ParseKeyList(lines)
}
