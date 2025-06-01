package common

import (
	"encoding/json"
	"path/filepath"
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

func NormalizePath(path string, baseDir string) string {
	filename := path
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(baseDir, filename)
	}
	return filepath.Clean(filename)
}

func ToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func ToJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
