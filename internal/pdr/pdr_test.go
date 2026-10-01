// SPDX-License-Identifier: AGPL-3.0-only

package pdr

import (
	"encoding/json"
	"testing"
)

// A detail is exactly its documented shape: {path, hint} for findings,
// {license, url} for a missing acceptance (API §3, §6.2) — never both.
func TestDetailShapes(t *testing.T) {
	for _, tc := range []struct {
		in   Detail
		want string
	}{
		{Detail{Path: "services.gamma", Hint: "needs a secret"}, `{"path":"services.gamma","hint":"needs a secret"}`},
		{Detail{Code: "PDR-E101", Path: "lab.yaml:4", Hint: "bad"}, `{"code":"PDR-E101","path":"lab.yaml:4","hint":"bad"}`},
		{Detail{License: "example-terms", URL: "https://example.com/terms"}, `{"license":"example-terms","url":"https://example.com/terms"}`},
	} {
		got, err := json.Marshal(tc.in)
		if err != nil || string(got) != tc.want {
			t.Errorf("%+v → %s (%v), want %s", tc.in, got, err, tc.want)
		}
	}
}

// Every code constant must have a registry entry with the full anatomy —
// the same-change rule made executable.
func TestEveryCodeRegistered(t *testing.T) {
	for _, code := range []string{
		CodeConfigUnreadable,
		CodeConfigUnknownKey,
		CodeConfigInvalid,
		CodeInstallFailed,
		CodeUninstallInstance,
		CodeUninstallStopFailed,
		CodeUninstallUnreadable,
		CodeServiceControl,
		CodeLabUnreadable,
		CodeLabSchema,
		CodeLabReference,
		CodeLabStructure,
		CodeLabComposition,
		CodeLabRetired,
		CodeTemplateRetired,
		CodeObjectiveGreenAtCreate,
		CodePlaybookNoObjectives,
		CodeRetiredPresent,
		CodeInstanceUnsupported,
		CodeLicenseRequired,
		CodeInstanceExists,
		CodeInstanceBusy,
		CodeInstanceNotFound,
		CodeDestroyConfirm,
		CodeRuntimeFailed,
		CodeReadinessBudget,
		CodeInstanceName,
		CodeTemplateNotFound,
		CodeEngineUnavailable,
		CodeRuntimeRootful,
		CodeEngineRunning,
		CodeStateNewer,
		CodeCreateRequest,
		CodeResetConfirm,
		CodeSetupFailed,
		CodeGatewayBind,
		CodeUnauthenticated,
		CodeLoginFailed,
		CodeLoginThrottled,
		CodeLoginLocked,
		CodeScopeInsufficient,
		CodeCSRF,
		CodeNoOperator,
		CodePasswordPolicy,
		CodeTokenExists,
		CodeTokenNotFound,
		CodeOperatorExists,
		CodeSessionRefused,
		CodePublicThrottled,
		CodeCheckpointError,
		CodeCheckpointTimeout,
		CodeAdapterUnavailable,
		CodeCheckpointNotFound,
		CodeSeedFailed,
		CodeSeedNotFound,
		CodeProgressRefused,
		CodePlaybookNotFound,
		CodeSecretNotFound,
		CodeEvidenceNotFound,
		CodeAttestRefused,
		CodeBaselineFailed,
		CodeServiceNotFound,
		CodeUpgradeRefused,
		CodeExplainUnknown,
		CodeSecretStoreUnreadable,
		CodeExecPull,
		CodeExecExit,
		CodeExecTimeout,
		CodeExecOutput,
		CodeExecRoot,
		CodeLabInitTarget,
	} {
		e, ok := Lookup(code)
		if !ok {
			t.Fatalf("code %s has no registry entry", code)
		}
		if e.Title == "" || e.Cause == "" || e.Next == "" {
			t.Fatalf("code %s entry incomplete: %+v", code, e)
		}
	}
	if got, want := len(Codes()), 71; got != want {
		t.Fatalf("registry has %d codes, constants list %d — keep them in lockstep", got, want)
	}
}
