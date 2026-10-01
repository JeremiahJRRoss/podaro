// SPDX-License-Identifier: AGPL-3.0-only

package auth

import "time"

// Whoami is GET /auth/session's body (API §2.2): who the caller is, by
// which mechanism, with what scope, and the CSRF token cookie writes
// must echo. The console's session fragment renders exactly this.
type Whoami struct {
	Subject   string     `json:"subject"`
	Mechanism string     `json:"mechanism"`
	Scope     string     `json:"scope"`
	Instance  string     `json:"instance,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	CSRF      string     `json:"csrf,omitempty"`
}
