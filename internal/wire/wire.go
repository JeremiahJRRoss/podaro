// SPDX-License-Identifier: AGPL-3.0-only

// Package wire holds the small grammars a value must satisfy before the
// engine puts it on an HTTP wire — a number written as digits, a Host,
// a field name — so the seed generators and the verify adapter judge an
// authored value by one rule and refuse it before any request, never
// after the transport has rewritten or zeroed it.
package wire

import (
	"net"
	"strings"
)

// Digits reads a number written as decimal digits only: no sign, no
// space, no other character. A value beyond a billion is refused rather
// than wrapped.
func Digits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000_000 {
			return 0, false
		}
	}
	return n, true
}

// ValidHost reports whether h is RFC 9110 §7.2's Host: a host — a DNS
// name of RFC 1123 labels, an IPv4 address, or an IPv6 literal in
// brackets — followed at most by a colon and a decimal port from 1 to
// 65535. It parses the grammar rather than filter characters, so
// `tenant:abc`, `[`, `%20` or a second colon are refused, not sent.
func ValidHost(h string) bool {
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return false
		}
		literal := h[1:end]
		if ip := net.ParseIP(literal); ip == nil || !strings.Contains(literal, ":") {
			return false
		}
		rest := h[end+1:]
		if rest == "" {
			return true
		}
		return strings.HasPrefix(rest, ":") && validPort(rest[1:])
	}
	host := h
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		host = h[:i]
		if strings.Contains(host, ":") || !validPort(h[i+1:]) {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil
	}
	return validDNSName(host)
}

func validPort(p string) bool {
	n, ok := Digits(p)
	return ok && n >= 1 && n <= 65535
}

// validDNSName is RFC 1123's host name: labels of letters, digits and
// hyphens, one to sixty-three long, neither starting nor ending with a
// hyphen, joined by dots, at most 253 in all.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidFieldName is RFC 9110 §5.1's token: one or more tchar.
func ValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
