// SPDX-License-Identifier: AGPL-3.0-only

package wire

import "testing"

func TestDigitsAreDigitsOnly(t *testing.T) {
	for s, want := range map[string]int{"0": 0, "7": 7, "007": 7, "65535": 65535, "1000000000": 1_000_000_000} {
		if n, ok := Digits(s); !ok || n != want {
			t.Fatalf("%q: want %d, got %d %v", s, want, n, ok)
		}
	}
	for _, s := range []string{"", "+1", "-1", " 1", "1 ", "1.0", "1e3", "0x10", "٣", "1_000", "10000000001"} {
		if n, ok := Digits(s); ok {
			t.Fatalf("%q is not a string of digits, read as %d", s, n)
		}
	}
}

func TestValidHostIsTheGrammarNotACharacterSet(t *testing.T) {
	for _, h := range []string{"collector", "collector:8088", "tenant-a.collector.test", "tenant-a.collector.test:443", "10.0.0.1", "10.0.0.1:9090", "[::1]", "[::1]:8088", "[2001:db8::1]", "localhost:1", "a1.b2", "x"} {
		if !ValidHost(h) {
			t.Fatalf("%q is a legal Host", h)
		}
	}
	for _, h := range []string{"", "tenant:abc", "[", "]", "%", "tenant%20a", "tenant a", "tenant/x", "tenant?x", "tenant:0", "tenant:65536", "tenant:8088:1", "tenant:+80", "tenant: 80", "-bad.example", "bad-.example", "a..b", ".a", "a.", "[::1", "[::1]x", "[zz]", "[10.0.0.1]", "::1", "a_b", "tenant:", "user@host", "a\tb", "ünïcode.example"} {
		if ValidHost(h) {
			t.Fatalf("%q is not a legal Host", h)
		}
	}
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if ValidHost(long) || ValidHost(long+".example") {
		t.Fatal("a label of 64 is not a label")
	}
}

func TestValidFieldNameIsAToken(t *testing.T) {
	for _, n := range []string{"X-Team", "content-type", "x", "a!#$%&'*+-.^_`|~z"} {
		if !ValidFieldName(n) {
			t.Fatalf("%q is a token", n)
		}
	}
	for _, n := range []string{"", "X Team", "X:Team", "X\tTeam", "X(Team)", "X/Team", "Ünïcode"} {
		if ValidFieldName(n) {
			t.Fatalf("%q is not a token", n)
		}
	}
}
