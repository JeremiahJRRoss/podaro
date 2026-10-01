// SPDX-License-Identifier: AGPL-3.0-only

package brand

import "testing"

// The defaults are the project's own name and title. A build that sets
// them with -ldflags -X is the rebrand hack/rebrand_test.sh proves; this
// only holds the unset values to what the documents call the product.
func TestTheDefaultsAreTheProjectsName(t *testing.T) {
	if Name != "Podaro" {
		t.Errorf("Name = %q, want Podaro", Name)
	}
	if Title != "Podaro Community" {
		t.Errorf("Title = %q, want Podaro Community", Title)
	}
}
