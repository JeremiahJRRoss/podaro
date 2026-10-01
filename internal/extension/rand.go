// SPDX-License-Identifier: AGPL-3.0-only

package extension

import "crypto/rand"

func cryptoRandRead(b []byte) (int, error) { return rand.Read(b) }
