// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// The `json_path` expectation of the http adapter (spec 0001 §3): a
// dotted path with numeric indexes — `$.data.result[0].value[1]`,
// `$[0].title`, `$.status` — an operator, and a value. Small on purpose:
// the paths the catalog templates need, nothing a second language would
// bring (ADR-0002 rejected an expression DSL).

// jsonPathLookup walks a decoded JSON value by path; found is false when
// any step does not exist.
func jsonPathLookup(v any, path string) (any, bool, error) {
	p := strings.TrimSpace(path)
	if !strings.HasPrefix(p, "$") {
		return nil, false, fmt.Errorf("json_path %q must start with $", path)
	}
	p = p[1:]
	for p != "" {
		switch {
		case strings.HasPrefix(p, "."):
			p = p[1:]
			end := strings.IndexAny(p, ".[")
			var key string
			if end < 0 {
				key, p = p, ""
			} else {
				key, p = p[:end], p[end:]
			}
			if key == "" {
				return nil, false, fmt.Errorf("json_path %q: empty key", path)
			}
			m, ok := v.(map[string]any)
			if !ok {
				return nil, false, nil
			}
			v, ok = m[key]
			if !ok {
				return nil, false, nil
			}
		case strings.HasPrefix(p, "["):
			end := strings.IndexByte(p, ']')
			if end < 0 {
				return nil, false, fmt.Errorf("json_path %q: unterminated [", path)
			}
			tok := strings.Trim(p[1:end], `'"`)
			p = p[end+1:]
			if i, err := strconv.Atoi(tok); err == nil {
				list, ok := v.([]any)
				if !ok || i < 0 || i >= len(list) {
					return nil, false, nil
				}
				v = list[i]
				continue
			}
			m, ok := v.(map[string]any)
			if !ok {
				return nil, false, nil
			}
			v, ok = m[tok]
			if !ok {
				return nil, false, nil
			}
		default:
			return nil, false, fmt.Errorf("json_path %q: unexpected %q", path, p[:1])
		}
	}
	return v, true, nil
}

// compare judges observed against value with op. Numbers compare as
// numbers when both sides read as one (Prometheus returns "1" as a
// string; authors write value: "200" or 200); everything else compares as
// text. exists ignores the value.
func compare(op string, observed any, found bool, value any) (bool, error) {
	switch op {
	case "exists":
		return found, nil
	case "", "eq", "ne", "gt", "gte", "lt", "lte", "contains":
	default:
		return false, fmt.Errorf("json_path op %q is not one of eq, ne, gt, gte, lt, lte, contains, exists", op)
	}
	if op == "" {
		op = "eq"
	}
	if !found {
		return op == "ne", nil
	}
	// Integers compare exactly, whatever their size: two integer literals
	// that differ only beyond the 53 bits a double keeps — 9007199254740993
	// observed, 9007199254740992 expected — are different numbers, never
	// the same rounded one. Decimals and
	// exponents compare as doubles, as before.
	if io, ok := asInteger(observed); ok {
		if iv, ok := asInteger(value); ok {
			c := io.Cmp(iv)
			switch op {
			case "eq":
				return c == 0, nil
			case "ne":
				return c != 0, nil
			case "gt":
				return c > 0, nil
			case "gte":
				return c >= 0, nil
			case "lt":
				return c < 0, nil
			case "lte":
				return c <= 0, nil
			}
		}
	}
	if fo, ok := asNumber(observed); ok {
		if fv, ok := asNumber(value); ok {
			switch op {
			case "eq":
				return fo == fv, nil
			case "ne":
				return fo != fv, nil
			case "gt":
				return fo > fv, nil
			case "gte":
				return fo >= fv, nil
			case "lt":
				return fo < fv, nil
			case "lte":
				return fo <= fv, nil
			}
		}
	}
	so, sv := asText(observed), asText(value)
	switch op {
	case "eq":
		return so == sv, nil
	case "ne":
		return so != sv, nil
	case "contains":
		return strings.Contains(so, sv), nil
	case "gt":
		return so > sv, nil
	case "gte":
		return so >= sv, nil
	case "lt":
		return so < sv, nil
	case "lte":
		return so <= sv, nil
	}
	return false, nil
}

// integerLiteral is a JSON or YAML integer as written: an optional sign
// and digits, no fraction, no exponent.
var integerLiteral = regexp.MustCompile(`^-?[0-9]+$`)

// asInteger reads an integer exactly — a Go integer, or an integer literal
// carried by a json.Number or a string — as a big.Int; anything with a
// fraction or an exponent, or a float, is not one.
func asInteger(v any) (*big.Int, bool) {
	switch t := v.(type) {
	case int:
		return big.NewInt(int64(t)), true
	case int64:
		return big.NewInt(t), true
	case uint64:
		return new(big.Int).SetUint64(t), true
	case json.Number:
		if integerLiteral.MatchString(t.String()) {
			return new(big.Int).SetString(t.String(), 10)
		}
	case string:
		s := strings.TrimSpace(t)
		if integerLiteral.MatchString(s) {
			return new(big.Int).SetString(s, 10)
		}
	}
	return nil, false
}

func asNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

func asText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return "null"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
