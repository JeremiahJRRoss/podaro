// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import "crypto/rand"

// cryptoRand reads from crypto/rand.
type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }
