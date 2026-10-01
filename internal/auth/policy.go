// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bufio"
	"bytes"
	_ "embed"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// MinPasswordLength is INSTALL §2 step 5's "12+ characters".
const MinPasswordLength = 12

//go:embed common-passwords.txt
var commonPasswordsRaw []byte

var (
	commonOnce sync.Once
	common     map[string]struct{}
)

func commonPasswords() map[string]struct{} {
	commonOnce.Do(func() {
		common = map[string]struct{}{}
		sc := bufio.NewScanner(bytes.NewReader(commonPasswordsRaw))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			common[strings.ToLower(line)] = struct{}{}
		}
	})
	return common
}

// CheckPassword applies the documented policy: at least 12 characters and
// not on the embedded common-password list (case-insensitive). The error
// is PDR-E307 with the reason as its cause.
func CheckPassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		e := pdr.New(pdr.CodePasswordPolicy, "password is shorter than %d characters", MinPasswordLength)
		e.Cause = "the policy is 12+ characters (INSTALL §2 step 5)"
		e.Next = "choose a longer password"
		return e
	}
	if _, bad := commonPasswords()[strings.ToLower(password)]; bad {
		e := pdr.New(pdr.CodePasswordPolicy, "password is on the common-password list")
		e.Cause = "it appears in a list of the most-used passwords; an attacker tries those first"
		e.Next = "choose a password that is not a well-known one"
		return e
	}
	return nil
}

// CheckUsername keeps usernames to the same label shape as instance
// names: lowercase letters, digits, hyphens, dots and underscores, 1–32
// characters — the audit stream prints them beside hostnames.
func CheckUsername(name string) error {
	if name == "" || len(name) > 32 {
		e := pdr.New(pdr.CodePasswordPolicy, "username must be 1–32 characters")
		e.Next = "choose a short lowercase username"
		return e
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			e := pdr.New(pdr.CodePasswordPolicy, "username %q contains %q — lowercase letters, digits, '-', '.', '_' only", name, string(r))
			e.Next = "choose a username like jross"
			return e
		}
	}
	return nil
}
