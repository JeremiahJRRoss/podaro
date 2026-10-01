// SPDX-License-Identifier: AGPL-3.0-only

package state

import "testing"

func TestMemoryStoreConformance(t *testing.T) {
	RunStoreTests(t, func(t *testing.T) Store { return NewMemory() })
}
