// K8shell user string parser
//
// Spec summary (v1.0):
//
//	USERSTR = user [ "~" ws-spec ]
//	ws-spec = bp-name | param-list
//	param-list = kv *( "+" kv )
//	kv = key "=" value
//
// - Percent-decode only blueprint names and values (NOT keys).
// - Keys are normalized to lowercase.
// - Slash "/" is allowed; when escaped as %2F it is decoded back to "/".
// - Reserved delimiters: @ ~ + = (use %XX inside values if literal needed).
package userstr

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	MAX_LOCAL_LEN = 64
	MAX_TOTAL_LEN = 128
)

var (
	ErrBadParam = errors.New("userstr: bad param (expected key=value)")
	ErrTooLong  = errors.New("userstr: identifier too long")
)

// UserStr is the parsed representation of a user string.
type UserStr struct {
	Raw       string            // original input
	User      string            // user (left of ~ or whole local if no ~)
	Blueprint *string           // direct blueprint name (if no params)
	Params    map[string]string // normalized keys to values (if params form)
}

// Parse parses a user string using default length constraints.
func Parse(input string) (*UserStr, error) {
	if MAX_TOTAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_TOTAL_LEN {
		return nil, fmt.Errorf("%w: total>%d", ErrTooLong, MAX_TOTAL_LEN)
	}

	if MAX_LOCAL_LEN > 0 && utf8.RuneCountInString(input) > MAX_LOCAL_LEN {
		return nil, fmt.Errorf("%w: local>%d", ErrTooLong, MAX_LOCAL_LEN)
	}

	user, wsSpec, _ := cutOnce(input, "~")

	if wsSpec == "" {
		return &UserStr{
			Raw:       input,
			User:      user,
			Blueprint: nil,
			Params:    nil,
		}, nil
	}

	if !strings.Contains(wsSpec, "=") {
		decoded, err := url.PathUnescape(wsSpec)
		if err != nil {
			return nil, fmt.Errorf("userstr: blueprint percent-decode: %w", err)
		}
		return &UserStr{
			Raw:       input,
			User:      user,
			Blueprint: &decoded,
			Params:    nil,
		}, nil
	}

	pairs := strings.Split(wsSpec, "+")
	params := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if p == "" {
			return nil, fmt.Errorf("%w: empty pair", ErrBadParam)
		}
		k, v, ok := cutOnce(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%w: %q", ErrBadParam, p)
		}

		if strings.Contains(v, "=") {
			return nil, fmt.Errorf("%w: unescaped '=' in value: %q", ErrBadParam, p)
		}

		k = strings.ToLower(k)

		val, err := url.PathUnescape(v)
		if err != nil {
			return nil, fmt.Errorf("%w: value decode failed for key %q: %v", ErrBadParam, k, err)
		}

		params[k] = val
	}

	return &UserStr{
		Raw:       input,
		User:      user,
		Blueprint: nil,
		Params:    params,
	}, nil
}

// cutOnce splits s at the first instance of sep. Returns before, after, and whether sep was found.
func cutOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
