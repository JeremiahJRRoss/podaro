// SPDX-License-Identifier: AGPL-3.0-only

package engine

import "crypto/tls"

// insecureTLS is the probe's TLS posture toward lab products: labs are
// deliberately permissive and their in-lab certificates are self-signed
// (an event collector's HTTPS input, for one); the probe asks "is it
// answering", not "is it trusted". Operator-facing TLS (the gateway, S5)
// is never configured this way.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // lab-internal readiness only
}
