// SPDX-License-Identifier: AGPL-3.0-only

// Package pdr defines Podaro's stable error codes and the embedded
// explain registry. Every code the engine emits has an Entry here, added
// in the same change that introduces the code (the project's engineering
// rule); `podaro explain` gains a command surface at plan step S9.
package pdr

import (
	"fmt"
	"sort"
	"strings"
)

// Error is the one error envelope (API §3): stable code, message, and the
// cause → evidence → next anatomy the CLI prints and the console renders.
type Error struct {
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Cause    string   `json:"cause,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Next     string   `json:"next,omitempty"`
	Details  []Detail `json:"details,omitempty"`
}

// Detail is a structured sub-item whose shape follows the code that
// carries it (API §3, §6.2): a config key or manifest finding is
// {path, hint} (Code set when the item carries its own code — lab
// validation lists every finding under one envelope); a missing license
// acceptance (PDR-E031, 428) is {license, url}. Empty fields are omitted
// so each item is exactly its documented shape.
type Detail struct {
	Code    string `json:"code,omitempty"`
	Path    string `json:"path,omitempty"`
	Hint    string `json:"hint,omitempty"`
	License string `json:"license,omitempty"`
	URL     string `json:"url,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// New builds an Error for a registered code. Using an unregistered code is
// a programming error, enforced by tests over emitted codes.
func New(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Registered codes emitted as of plan step S1.
const (
	// Configuration (User Manual §4).
	CodeConfigUnreadable = "PDR-E010"
	CodeConfigUnknownKey = "PDR-E011"
	CodeConfigInvalid    = "PDR-E012"
	// System lifecycle (INSTALL §2, §7).
	CodeInstallFailed       = "PDR-E020"
	CodeUninstallInstance   = "PDR-E021"
	CodeUninstallStopFailed = "PDR-E022"
	CodeUninstallUnreadable = "PDR-E026"
	CodeUpgradeRefused      = "PDR-E025"
	CodeServiceControl      = "PDR-E027"
	// Lab manifests (plan S3: lab validate / lab plan — API §6, spec 0001
	// §9, spec 0003 §11). Warnings W1xx are spec 0001's authoring warnings.
	CodeLabUnreadable          = "PDR-E100"
	CodeLabSchema              = "PDR-E101"
	CodeLabReference           = "PDR-E102"
	CodeLabStructure           = "PDR-E103"
	CodeLabComposition         = "PDR-E104"
	CodeLabInitTarget          = "PDR-E105"
	CodeLabRetired             = "PDR-E106"
	CodeTemplateRetired        = "PDR-E107"
	CodeObjectiveGreenAtCreate = "PDR-W101"
	CodePlaybookNoObjectives   = "PDR-W102"
	// Retired content an earlier build left — a catalog entry or an
	// instance of a template the retirement manifest lists — present and
	// unsupported by this release (the reconciliation plan's R3). A
	// warning: it is reported, never raised as a refusal (PDR-E215 is).
	CodeRetiredPresent = "PDR-W103"
	// Instances and jobs (plan S4: create/destroy/reconcile — API §4, §7).
	CodeLicenseRequired   = "PDR-E031" // API §6.2, documented there
	CodeInstanceExists    = "PDR-E200"
	CodeInstanceBusy      = "PDR-E201"
	CodeInstanceNotFound  = "PDR-E202"
	CodeDestroyConfirm    = "PDR-E203"
	CodeRuntimeFailed     = "PDR-E204"
	CodeReadinessBudget   = "PDR-E205"
	CodeInstanceName      = "PDR-E206"
	CodeTemplateNotFound  = "PDR-E207"
	CodeEngineUnavailable = "PDR-E208"
	CodeRuntimeRootful    = "PDR-E209"
	CodeEngineRunning     = "PDR-E210"
	CodeStateNewer        = "PDR-E211"
	CodeCreateRequest     = "PDR-E212"
	CodeResetConfirm      = "PDR-E213"
	CodeServiceNotFound   = "PDR-E214"
	// An operation on an instance of a retired template (R3): the answer
	// of verify, seed, reset, a checkpoint run and a playbook action.
	CodeInstanceUnsupported = "PDR-E215"

	// Setup and the gateway (INSTALL §2 step 4; plan S5).
	CodeSetupFailed = "PDR-E023"
	CodeGatewayBind = "PDR-E024"

	// Authentication and authorization (API §2; plan S5).
	CodeUnauthenticated   = "PDR-E300"
	CodeLoginFailed       = "PDR-E301"
	CodeLoginThrottled    = "PDR-E302"
	CodeLoginLocked       = "PDR-E303"
	CodeScopeInsufficient = "PDR-E304"
	CodeCSRF              = "PDR-E305"
	CodeNoOperator        = "PDR-E306"
	CodePasswordPolicy    = "PDR-E307"
	CodeTokenExists       = "PDR-E308"
	CodeTokenNotFound     = "PDR-E309"
	CodeOperatorExists    = "PDR-E310"
	CodeSessionRefused    = "PDR-E311"
	// The public routes — GET /system/legal and the /legal page — answer
	// without a session, per source, like the login form (API §2; the
	// reconciliation plan's R5). E312–E314 are the P2 draft's reservation.
	CodePublicThrottled = "PDR-E315"

	// Checkpoints, seeds, evidence, progress (plan S6 — spec 0001 §4,
	// API §7–§10).
	CodeCheckpointError    = "PDR-E400"
	CodeCheckpointTimeout  = "PDR-E401"
	CodeAdapterUnavailable = "PDR-E402"
	CodeCheckpointNotFound = "PDR-E403"
	CodeSeedFailed         = "PDR-E404"
	CodeSeedNotFound       = "PDR-E405"
	CodeProgressRefused    = "PDR-E406"
	CodePlaybookNotFound   = "PDR-E407"
	CodeSecretNotFound     = "PDR-E408"
	CodeEvidenceNotFound   = "PDR-E409"
	CodeAttestRefused      = "PDR-E410"
	CodeBaselineFailed     = "PDR-E411"
	// The instance's secret store cannot be read, so no result, report,
	// journal line or failure record is produced.
	CodeSecretStoreUnreadable = "PDR-E412"

	// `podaro explain` and its API twin (plan S9, API §5).
	CodeExplainUnknown = "PDR-E413"

	// The exec extension contract (Spec 0002 §6; plan S6).
	CodeExecPull    = "PDR-E501"
	CodeExecExit    = "PDR-E502"
	CodeExecTimeout = "PDR-E503"
	CodeExecOutput  = "PDR-E504"
	CodeExecRoot    = "PDR-E505"
)

// Entry is one explain-registry record: what `podaro explain PDR-*`
// renders offline (API §5, `GET /system/errors/{code}`).
type Entry struct {
	Code       string `json:"code"`
	Title      string `json:"title"`
	Cause      string `json:"cause"`
	Background string `json:"background,omitempty"`
	Next       string `json:"next"`
}

var registry = map[string]Entry{
	CodeConfigUnreadable: {
		Code:       CodeConfigUnreadable,
		Title:      "configuration file unreadable or not valid YAML",
		Cause:      "~/.config/podaro/config.yaml exists but could not be read or parsed",
		Background: "The config file is strict YAML (User Manual §4). Parse failures carry file:line.",
		Next:       "fix the YAML at the printed file:line, or remove the file and re-run podaro setup",
	},
	CodeConfigUnknownKey: {
		Code:       CodeConfigUnknownKey,
		Title:      "configuration contains an unknown key",
		Cause:      "a key in config.yaml is not part of the documented configuration surface",
		Background: "Unknown keys fail loudly with file:line rather than being ignored, so a typo can never silently disable what you meant to configure (User Manual §4 lists every key).",
		Next:       "fix or remove the key at the printed file:line",
	},
	CodeConfigInvalid: {
		Code:       CodeConfigInvalid,
		Title:      "configuration value invalid",
		Cause:      "a config.yaml value fails validation (range, enum, file permissions, or reference)",
		Background: "Examples: gateway.port outside 1–65535; an observability exporter other than otlp|http|hec; traces with a non-OTLP exporter (OTLP-only in this release); a token_file that is missing or not mode 0600.",
		Next:       "correct the named key per User Manual §4",
	},
	CodeUpgradeRefused: {
		Code:       CodeUpgradeRefused,
		Title:      "system upgrade did not happen",
		Cause:      "the release could not be resolved or downloaded, its checksum did not match the release manifest, the version asked for is older than the running one, the binary could not be replaced, or another upgrade is already running",
		Background: "Upgrade downloads the binary and the release's SHA256SUMS, verifies the digest locally, and only then backs up the state database and replaces the binary — so every failure before the replacement leaves the running install exactly as it was, and the download is discarded (INSTALL §6). A checksum mismatch is never overridden. Downgrades are refused because migrations are forward-only: an older binary refuses a state database a newer one migrated (PDR-E211), so a rollback restores the binary and the state backup together — which is also why one upgrade runs at a time, on an advisory lock held for the whole sequence: a second one beside the first would write the already-migrated state over the backup the first made, leaving that pair with no backup the old binary can open.",
		Next:       "read the cause · re-run podaro system upgrade · --from <url> for a mirror on a host with no route out",
	},
	CodeInstallFailed: {
		Code:       CodeInstallFailed,
		Title:      "system install step failed",
		Cause:      "one of the install steps (directories, asset extraction, user service, socket) did not complete",
		Background: "Install is self-extraction plus a systemd user service — never root, never sudo (INSTALL §2). A missing systemd user session is the usual cause on containers and minimal hosts.",
		Next:       "read the failed step's message, fix the environment, and re-run podaro system install (idempotent)",
	},
	CodeUninstallInstance: {
		Code:       CodeUninstallInstance,
		Title:      "uninstall refused: instances still exist",
		Cause:      "the state directory holds one or more instances",
		Background: "Destroying labs is a per-lab decision made by name, never a side effect of removing software (INSTALL §7).",
		Next:       "podaro destroy <instance> for each, then re-run podaro system uninstall",
	},
	CodeUninstallUnreadable: {
		Code:       CodeUninstallUnreadable,
		Title:      "uninstall aborted: the instance list could not be read",
		Cause:      "the instances directory under the state directory exists but could not be listed",
		Background: "Uninstall refuses while instances exist (INSTALL §7), so it has to know whether any do. A directory it cannot read is not an empty one: the answer is unknown, and an unknown answer aborts the run with nothing removed — the same rule the stop check applies to engine liveness (PDR-E022).",
		Next:       "make the instances directory readable · podaro status · then re-run podaro system uninstall",
	},
	CodeServiceControl: {
		Code:       CodeServiceControl,
		Title:      "the service could not be started, stopped, restarted or read",
		Cause:      "systemctl --user could not act on podaro.service, or the engine did not answer on its socket after a start or restart",
		Background: "podaro.service is the systemd user unit system install writes (INSTALL §3); start, stop, restart and status drive it through systemctl --user with the account's session filled in, so they work from a login shell of the account (sudo -iu podaro) and through podaroctl (INSTALL §2 step 6). A unit systemd does not know means system install has not run for this account. A bus it cannot reach means the account has no service manager to talk to: lingering (loginctl enable-linger) keeps one alive without a login, and the shell needs the session variables the installer's profile block sets. An engine that starts but does not answer within 30 s is failing reconcile-on-start; its journal says why.",
		Next:       "podaro system status · journalctl --user -u podaro · when the bus is unreachable: sudo loginctl enable-linger <account> · when the unit is unknown: podaro system install",
	},
	CodeUninstallStopFailed: {
		Code:       CodeUninstallStopFailed,
		Title:      "uninstall aborted: engine service could not be stopped",
		Cause:      "systemctl --user failed to stop podaro.service and the engine may still be running",
		Background: "Uninstall never removes state or configuration while the engine could be alive. Tolerated only when stopping is affirmatively unnecessary: systemd reports the unit inactive, or — with the user bus unreachable — no `systemd --user` manager runs for this user (a live manager could be mid-Restart=on-failure), no engine process exists, and the socket is absent or a dead leftover. Unprovable states abort.",
		Next:       "systemctl --user stop podaro.service · journalctl --user -u podaro · then re-run podaro system uninstall",
	},
	CodeLabUnreadable: {
		Code:       CodeLabUnreadable,
		Title:      "lab manifest unreadable or not one YAML document",
		Cause:      "a template path, lab.yaml, playbook, or module file could not be read or parsed",
		Background: "A template is one directory: lab.yaml plus playbooks/*.yaml (spec 0003 §1). Each file is exactly one YAML document; parse failures carry file:line.",
		Next:       "check the path, fix the YAML at the printed file:line, then re-run podaro lab validate",
	},
	CodeLabSchema: {
		Code:       CodeLabSchema,
		Title:      "lab manifest does not match the schema of its apiVersion",
		Cause:      "a template, module, or playbook has a wrong or missing field, or a value of the wrong shape",
		Background: "Shapes are the frozen schemas under schemas/ (specs 0001 and 0003) — v1alpha2, the current contract, or v1alpha1, frozen history the engine still reads — chosen by each document's apiVersion: unknown keys are refused, images must be digest-pinned, ids are DNS labels, durations are like 30s or 5m. The schema header line in each file gives editors inline validation (Manual §11).",
		Next:       "fix each detail at its file:line; compare against the schema named in the file's first line",
	},
	CodeLabReference: {
		Code:       CodeLabReference,
		Title:      "lab manifest references something that does not exist",
		Cause:      "a use:, seed:, checkpoint ref, context, reveal:, ${secret:…}, adapter, generator, profile service, init target, or init auth secret names nothing declared",
		Background: "Referential integrity is spec 0001 §9 across the template and its playbooks, and spec 0003 §11 across the composition: seeds, checkpoint ids, service names (or overview), declared secret names (template plus composed modules), the installed module library, and the adapter/generator registries plus composed module aliases.",
		Next:       "declare the missing thing or fix the name at the printed file:line (the message lists what is declared)",
	},
	CodeLabStructure: {
		Code:       CodeLabStructure,
		Title:      "lab manifest breaks a structural rule",
		Cause:      "duplicate ids in one scope, an objective checkpoint without a hint, duplicate playbook names, a repro-only playbook that does not open with an auto step, a ${secret:…} reference somewhere create never renders (a seed or checkpoint), an init request's header field declared twice in different cases, or an init auth username carrying a colon",
		Background: "Spec 0001 §2 and §9: ids are unique per scope (an inline checkpoint may not shadow a template-level one — reference it with {ref: id} instead); hints are required on objectives because the hint is the teaching assistant; repro breakpoints are defined by the first non-auto step.",
		Next:       "rename, add the hint, or reorder at the printed file:line",
	},
	CodeLabComposition: {
		Code:       CodeLabComposition,
		Title:      "template composition breaks a spec 0003 §11 rule",
		Cause:      "a use: reference disagrees with the module's metadata, the licenses: list differs from the composed EULA set, an alias name collides or shadows a built-in, a shared secret is declared with two kinds, or the merged config is not a valid module",
		Background: "Composition rules: name and version in use: must equal the module's metadata; licenses: must list exactly the EULA ids the modules and inline services declare (acceptance is gated on it, API §6.2); alias names may not shadow built-ins or each other; config: deep-merges onto the module (maps merge, arrays and scalars replace) and the result must still satisfy the module schema.",
		Next:       "align the list or name at the printed file:line; podaro lab plan shows the composed licenses and exec images",
	},
	CodeLabInitTarget: {
		Code:       CodeLabInitTarget,
		Title:      "lab init cannot scaffold into this directory",
		Cause:      "the target already holds files, its name cannot be a template name, no --from was given, or the scaffold could not be written",
		Background: "`lab init --from <template> <dir>` writes a new template and never merges into an existing one, and the scaffold is named after its directory — so the directory name has to satisfy metadata.name's DNS-label rule (spec 0003 §2). Every refusal happens before the first file is written (User Manual §11).",
		Next:       "choose an empty or absent directory whose name is a DNS label, and name a template with --from",
	},
	CodeLabRetired: {
		Code:       CodeLabRetired,
		Title:      "lab manifest names a retired adapter, generator or module",
		Cause:      "a checkpoint's adapter, a seed's generator, or a service's use: names an identifier the owner retired on 2026-09-23 with the lab it served; the finding names the identifier and the role the retirement manifest records for it",
		Background: "The retirement is recorded in the retirement manifest the binary embeds (hack/retirement.json; ADR-0004 D9; the reconciliation plan's R2). The v1alpha2 contract (spec 0001 §11, spec 0003 §13) removed those names from the registries; v1alpha1 documents are still read, and the rule applies to both versions, so a document that names a retired identifier fails validation before any plan or pull. Nothing substitutes a retained adapter, generator or module for it.",
		Next:       "remove the checkpoint, or judge it with http, container or an exec adapter of your own; remove the seed, or generate with web-logs, http-requests or an exec generator; remove the service, or bring its image as an inline service pinned by digest (spec 0003 §3) — then podaro lab validate again",
	},
	CodeTemplateRetired: {
		Code:       CodeTemplateRetired,
		Title:      "template retired",
		Cause:      "up or lab init --from named a template the retirement manifest lists — refused before validation, whatever the installed catalog holds — or up was given a directory whose lab.yaml declares that name",
		Background: "The owner retired that template on 2026-09-23 (ADR-0004 D9; the reconciliation plan's R2 and R3), and no release carries it. The retirement manifest the binary embeds (hack/retirement.json) is what names it; nothing recreates, repairs or offers it — a copy an earlier build left in the catalog stays on disk and is never offered (PDR-W103). A template of your own under another name is validated like any other, and one that names a retired adapter, generator or module fails with PDR-E106.",
		Next:       "podaro up <one of the installed templates the refusal lists>, or podaro up ./path/to/your-template under a name of its own · podaro lab init --from <one of those> <dir>",
	},
	CodeRetiredPresent: {
		Code:       CodeRetiredPresent,
		Title:      "retired content present, unsupported by this release",
		Cause:      "the installed catalog holds a template the retirement manifest lists, or an earlier build created an instance from one",
		Background: "The owner retired that template on 2026-09-23 with the adapters, generators and modules it used (ADR-0004 D9; the reconciliation plan's R3), and no release carries it. Nothing an earlier build left is deleted, stopped or rewritten. The catalog entry stays on disk and is never offered: the install board, podaro status on a host with no instances and the installed-names line of a refusal leave it out, the board and status say once that it is there, and up or lab init --from it is refused (PDR-E107). An instance of it is marked unsupported: the engine never reconciles, repairs, restarts or stops it — its containers are left exactly as they are — and says so in its log once per start and in the instance's evidence once; podaro status shows it as unsupported · retired template, its evidence and its reports still read, and every operation that would run the lab is refused (PDR-E215). podaro system upgrade lists both before it replaces anything.",
		Next:       "podaro status <instance> · save what you need from its evidence and reports · podaro destroy <instance> when you are done with it, the only act that removes it · a catalog entry is yours to remove from catalog/ under the state directory",
	},
	CodeObjectiveGreenAtCreate: {
		Code:       CodeObjectiveGreenAtCreate,
		Title:      "objective checkpoint passed at create (authoring warning)",
		Cause:      "an objective was green before any learner work — it verifies something the template already makes true",
		Background: "Objectives are the learner's work and are expected red at create (spec 0001 §1). Green at create usually means the checkpoint belongs in the template's baseline list, or the seed pre-satisfies it. Emitted by create/verify (plan step S6).",
		Next:       "move the checkpoint to the template's checkpoints: list as a baseline, or change what the seed makes true",
	},
	CodeLicenseRequired: {
		Code:       CodeLicenseRequired,
		Title:      "license acceptance required",
		Cause:      "the template composes a proprietary product whose EULA has not been accepted for this create",
		Background: "Podaro never defaults a EULA to accepted (API §6.2, spec 0003 §7). Acceptance is explicit, per create, and recorded in evidence with actor and timestamp; the acceptance environment is injected only afterwards.",
		Next:       "re-run with --accept-license <id> for each listed license (podaro up prompts interactively on a TTY)",
	},
	CodeInstanceExists: {
		Code:       CodeInstanceExists,
		Title:      "instance name already exists",
		Cause:      "an instance of that name is recorded in engine state",
		Background: "Instance names become hostnames and namespace every container, network, and secret (invariant 5), so they are unique per host.",
		Next:       "pick another --name, or podaro destroy <name> first",
	},
	CodeInstanceBusy: {
		Code:       CodeInstanceBusy,
		Title:      "instance is busy with an exclusive job",
		Cause:      "a create, destroy, reset, seed, or verify job is queued or running for this instance",
		Background: "One exclusive job per instance at a time (API §4); checkpoint runs and reads are always allowed alongside. Jobs are persistent — interrupting the CLI detaches, it never cancels.",
		Next:       "podaro status <name> to follow the running job; retry when it finishes",
	},
	CodeInstanceNotFound: {
		Code:       CodeInstanceNotFound,
		Title:      "no such instance",
		Cause:      "engine state holds no instance of that name",
		Background: "Instances are listed by podaro status; names are lowercase DNS labels of at most 24 characters.",
		Next:       "podaro status to list instances",
	},
	CodeServiceNotFound: {
		Code:       CodeServiceNotFound,
		Title:      "no such service on this instance",
		Cause:      "the instance's template declares no service of that name, or the service has no container yet",
		Background: "Services are named by the template, and the ladder lists them: podaro status <instance> shows every service and the stage it reached. A service that exists but has no container yet belongs to an instance that has not got that far — the refusal says which of the two it is.",
		Next:       "podaro status <instance> to list its services",
	},
	CodeInstanceUnsupported: {
		Code:       CodeInstanceUnsupported,
		Title:      "operation refused: the instance's template is retired",
		Cause:      "verify, seed, reset, a checkpoint run, an attestation, a playbook action, or a read that needs the lab's plan (its checkpoints, playbooks, secrets or logs) was asked of an instance an earlier build created from a template the retirement manifest lists",
		Background: "The owner retired that template on 2026-09-23 (ADR-0004 D9; the reconciliation plan's R3), and no release carries it or the adapters, generators and modules it used, so this release cannot run the lab and never tries: nothing substitutes another adapter or module, and the engine never reconciles, repairs, restarts or stops the instance on its own (PDR-W103). Its containers, data, secrets and evidence are left as they were. What still works: podaro status, the evidence (GET /instances/<name>/evidence and each entry, the console's Evidence tab), the HTML and JUnit reports, and podaro destroy, which removes what the instance's labels name and nothing else.",
		Next:       "podaro status <name> · save its evidence and reports (GET /instances/<name>/evidence/report.html and report.junit.xml) · podaro destroy <name> when you no longer need it",
	},
	CodeDestroyConfirm: {
		Code:       CodeDestroyConfirm,
		Title:      "destroy confirmation does not match the instance name",
		Cause:      "the confirm value differs from the instance name",
		Background: "Destroy is total — containers, volumes, network, secrets, routes, state, evidence — so the API demands the name echoed back (API §7), and the CLI asks you to type it.",
		Next:       "podaro destroy <name> and type the name exactly, or pass --yes in scripts",
	},
	CodeRuntimeFailed: {
		Code:       CodeRuntimeFailed,
		Title:      "container runtime operation failed",
		Cause:      "a pull, network, create, start, stop, or remove call to the runtime returned an error",
		Background: "The engine drives rootless Podman at arm's length; the cause carries Podman's own message. Jobs are journaled and idempotent, so re-running the operation resumes at the failed step.",
		Next:       "read the cause; podaro doctor checks the runtime; re-run the command to resume",
	},
	CodeReadinessBudget: {
		Code:       CodeReadinessBudget,
		Title:      "service did not become healthy within its budget",
		Cause:      "the readiness probe kept failing past the module's declared start budget",
		Background: "Budgets are declared per module (spec 0003 §9.2: typical is what the ladder narrates, budget is the failure boundary). Exceeding one is a failure, not patience — the ladder stops at the last verified stage.",
		Next:       "podaro logs <instance> <service> for the product's own account; podaro doctor for host resources; podaro up again to resume",
	},
	CodeInstanceName: {
		Code:       CodeInstanceName,
		Title:      "invalid instance name",
		Cause:      "the name is not a lowercase DNS label of 1–24 characters, or a hostname it would claim (<instance>, <service>-<instance>) already belongs to a running instance or exceeds a DNS label's 63 characters",
		Background: "Names become hostnames (<instance>.<domain>, <service>-<instance>.<domain>) and object names, so they follow DNS label rules (API §7.1).",
		Next:       "choose a name like pii-lab: lowercase letters, digits, hyphens, at most 24 characters",
	},
	CodeTemplateNotFound: {
		Code:       CodeTemplateNotFound,
		Title:      "template not found",
		Cause:      "the argument is neither an existing directory nor a template in the installed catalog",
		Background: "up takes a catalog template name (the refusal lists the installed ones; podaro system install extracts the starter catalog into the state directory) or a path to a template directory holding lab.yaml.",
		Next:       "podaro up <one of the names above>, or podaro up ./path/to/template",
	},
	CodeEngineUnavailable: {
		Code:       CodeEngineUnavailable,
		Title:      "engine is not reachable on the local socket",
		Cause:      "the API socket is absent or refuses connections",
		Background: "The CLI is a client of the engine service (API §1: the local socket door). The service is installed and started by podaro system install and managed by systemd --user.",
		Next:       "systemctl --user status podaro · journalctl --user -u podaro · podaro doctor",
	},
	CodeRuntimeRootful: {
		Code:       CodeRuntimeRootful,
		Title:      "the container runtime is rootful; Podaro is rootless-only",
		Cause:      "podman info reports rootless: false for the user the engine runs as",
		Background: "Roadmap §1 invariant 8 and threat model B4: the platform stays hardened while its labs are permissive, and rootless Podman is the first wall. The engine refuses to serve rather than run labs as root; podaro doctor reports the same fact before install.",
		Next:       "run the engine as an unprivileged user with rootless Podman configured (User Manual §3) · podaro doctor",
	},
	CodeEngineRunning: {
		Code:       CodeEngineRunning,
		Title:      "another engine already serves this state directory",
		Cause:      "engine.lock is held by a live process, or the API socket accepted a connection",
		Background: "One engine per state directory is what makes the exclusive-job slot (API §4) a fact: a second engine would resume the same journaled jobs beside the first and unlink its socket. The lock is advisory and released when the process dies, so an unclean stop never leaves it behind; a stale socket with nothing answering is removed.",
		Next:       "systemctl --user status podaro · stop that engine before starting another · podaro doctor",
	},
	CodeStateNewer: {
		Code:       CodeStateNewer,
		Title:      "the state database is newer than this binary",
		Cause:      "state.db carries more applied migrations than this engine knows",
		Background: "Migrations run forward-only (Install §6): a newer Podaro extended the schema, and an older engine would read tables and invariants it does not understand — reads could fail unpredictably and writes could damage the newer data. The engine refuses to start rather than guess; nothing is read or written first. The pre-migration backup beside state.db is the state as the older schema left it.",
		Next:       "run the Podaro version that wrote state.db · or roll back binary and state together: stop the engine, then restore the backup beside state.db (state.db.bak-v<version>-<time>)",
	},
	CodeCreateRequest: {
		Code:       CodeCreateRequest,
		Title:      "the create request is malformed",
		Cause:      "the body is not one JSON object (undecodable, trailing data, or over 1 MiB), it names no source or both template and path, or its mode is not authoring or delivery",
		Background: "API §7.1: a create is one JSON object naming its source exactly once — a catalog template (a delivery instance) or a directory (an authoring instance, or delivery with --mode authoring|delivery). A body the engine cannot read as that object is refused before anything is looked up; one naming no source, both sources, or an unknown mode would leave the engine to guess what was meant, and is refused too — never reported as a missing template or a bad name.",
		Next:       "POST {\"template\"|\"path\", \"name\", \"profile\", \"mode\", \"accept_licenses\"} — one object, template or path, mode authoring or delivery · podaro up <template|dir> [--mode authoring|delivery]",
	},
	CodeResetConfirm: {
		Code:       CodeResetConfirm,
		Title:      "reset needs confirmation",
		Cause:      "reset was asked for with no terminal to confirm on and without --yes",
		Background: "Reset is destructive to the lab's data (User Manual §8): the containers and what they hold go, objective results and playbook progress are cleared; the instance, its secrets, and its evidence survive. The CLI shows that impact first and asks y/N (UX §7); scripts pass --yes, which is never the default.",
		Next:       "podaro reset <name> on a terminal, or podaro reset <name> --yes in scripts",
	},
	CodePlaybookNoObjectives: {
		Code:       CodePlaybookNoObjectives,
		Title:      "playbook has no objective checkpoints (authoring warning)",
		Cause:      "no step carries an inline checkpoint of class objective",
		Background: "A playbook with nothing to verify is a document (spec 0001 §9). It still validates and renders; the warning asks whether that is intended.",
		Next:       "add an inline checkpoint with a hint to the steps that teach something, or accept the warning for a narrative-only playbook",
	},
	CodeSetupFailed: {
		Code:       CodeSetupFailed,
		Title:      "setup step failed",
		Cause:      "one of the setup steps (config, certificate authority, wildcard certificate, gateway) did not complete",
		Background: "podaro setup writes config.yaml, generates the local CA and the wildcard leaf under the state directory, then asks the running engine to open the TLS gateway (INSTALL §2 step 4). The engine must be installed and running for the last step.",
		Next:       "read the failed row, fix the cause (podaro system install · podaro doctor), and re-run podaro setup — idempotent; the CA is reused",
	},
	CodeGatewayBind: {
		Code:       CodeGatewayBind,
		Title:      "gateway cannot listen on its port",
		Cause:      "binding the TLS listener failed — the port is in use, or the certificate and key could not be loaded",
		Background: "The gateway is the only network listener (INSTALL §3). It binds 0.0.0.0:<gateway.port> once a domain and certificates exist.",
		Next:       "podaro doctor (port check) · free the port or set gateway.port in config.yaml · re-run podaro setup",
	},
	CodeUnauthenticated: {
		Code:       CodeUnauthenticated,
		Title:      "credentials required",
		Cause:      "the request reached the network door without a valid session cookie or bearer token",
		Background: "Deny until authenticated (API §2): every /api route on the network requires credentials; only login, the join exchange, and the login page are open. The local socket needs none — possession of the user account is the credential.",
		Next:       "sign in at the console, or send Authorization: Bearer pdr_… (podaro auth token create)",
	},
	CodeLoginFailed: {
		Code:       CodeLoginFailed,
		Title:      "login failed",
		Cause:      "the username or password did not match the operator account",
		Background: "Failed attempts are counted per source and throttled with exponential backoff; five consecutive failures lock the source out for 15 minutes (API §2.1). There is no password recovery — podaro auth reset at the local socket replaces the account.",
		Next:       "check the username and password; after repeated failures wait for the printed Retry-After",
	},
	CodeLoginThrottled: {
		Code:       CodeLoginThrottled,
		Title:      "login throttled",
		Cause:      "a previous attempt from this source failed and its backoff has not elapsed",
		Background: "Backoff doubles per consecutive failure: 1 s, 2 s, 4 s, 8 s. Attempts inside the window are refused (429) and do not count as failures.",
		Next:       "wait the Retry-After seconds, then try again",
	},
	CodeLoginLocked: {
		Code:       CodeLoginLocked,
		Title:      "source locked out",
		Cause:      "five consecutive failed logins from this source",
		Background: "The lockout lasts 15 minutes; both it and its release are recorded in the system audit stream (API §2.5). A locked source cannot log in even with the right password.",
		Next:       "wait the Retry-After seconds; the operator can inspect the audit stream at the socket (GET /system/audit)",
	},
	CodeScopeInsufficient: {
		Code:       CodeScopeInsufficient,
		Title:      "insufficient scope",
		Cause:      "the credential's scope does not cover this endpoint",
		Background: "Tokens carry one scope: read (everything non-mutating, including verify and checkpoint runs), operate (read + seeds, resets, progress, attest), admin (everything). An instance-bound session carries the instance scope, below read: its own instance's status and jobs and its own session, nothing else (API §2.4). The response names the required scope (API §2.3).",
		Next:       "use a token with the named scope: podaro auth token create --name <name> --scope <scope>",
	},
	CodeCSRF: {
		Code:       CodeCSRF,
		Title:      "CSRF token missing or wrong",
		Cause:      "a cookie-authenticated write arrived without a matching X-Podaro-CSRF header",
		Background: "Cookie-authenticated non-GET requests must carry X-Podaro-CSRF, obtained from GET /auth/session (API §2.2). Bearer and socket callers are exempt — they hold no ambient credential.",
		Next:       "fetch GET /auth/session and send its csrf value as X-Podaro-CSRF; the console does this itself — reload the page",
	},
	CodeNoOperator: {
		Code:       CodeNoOperator,
		Title:      "no operator account yet",
		Cause:      "a login was attempted before podaro auth setup created the operator account",
		Background: "The one full account is created at the local socket by podaro auth setup (INSTALL §2 step 5); until then the network door has nothing to authenticate against.",
		Next:       "podaro auth setup",
	},
	CodePasswordPolicy: {
		Code:       CodePasswordPolicy,
		Title:      "password does not meet the policy",
		Cause:      "shorter than 12 characters, or on the embedded common-password list",
		Background: "INSTALL §2 step 5: 12+ characters, checked against a common-password list, hashed with Argon2id (64 MiB, 3 iterations) and stored in auth.json (0600) — never anywhere else.",
		Next:       "choose a longer or less common password and re-run podaro auth setup",
	},
	CodeTokenExists: {
		Code:       CodeTokenExists,
		Title:      "token name already exists",
		Cause:      "a token with this name is already issued",
		Background: "Token names are unique so listings and revocations are unambiguous (API §2.3).",
		Next:       "podaro auth token revoke <name> first, or pick another name",
	},
	CodeTokenNotFound: {
		Code:  CodeTokenNotFound,
		Title: "no such token",
		Cause: "no token with that name or id exists",
		Next:  "podaro auth token list",
	},
	CodeOperatorExists: {
		Code:       CodeOperatorExists,
		Title:      "operator account already exists",
		Cause:      "podaro auth setup was run again after the account was created",
		Background: "There is exactly one operator account. Replacing it is a deliberate, socket-only act: podaro auth reset rotates the session-signing key, which signs every console session out (INSTALL §2 step 5).",
		Next:       "podaro auth reset",
	},
	CodeSessionRefused: {
		Code:       CodeSessionRefused,
		Title:      "session not valid on this hostname",
		Cause:      "the session is bound to one instance and this hostname belongs to another, or to the operator console",
		Background: "Instance-access sessions (API §2.4) are engine-bound to their instance's hostnames; the gateway refuses them everywhere else (threat model B2).",
		Next:       "use the join link's own instance hostname, or sign in as the operator",
	},
	CodePublicThrottled: {
		Code:       CodePublicThrottled,
		Title:      "too many requests for a public page from this source",
		Cause:      "this source asked for the licence and source page (/legal, or GET /system/legal) faster than the gateway answers one source",
		Background: "The two public routes answer anyone, with no session, so they are rate-limited per source the way the login form is (API §2; threat model B1): a burst of 30 requests, then one every 2 seconds. The source is the peer address, never a forwarded header — behind your own reverse proxy every client shares one allowance. The page is static; `podaro legal` prints the same from the binary, offline.",
		Next:       "wait the Retry-After seconds, then load the page again · or run podaro legal on the host",
	},
	CodeCheckpointError: {
		Code:       CodeCheckpointError,
		Title:      "checkpoint could not be evaluated",
		Cause:      "the adapter could not ask the product: the service was unreachable, its answer was not what the adapter reads (not JSON, no such path), or the URL names a port the service does not declare as an endpoint",
		Background: "A checkpoint result of status error means the adapter could not evaluate (spec 0001 §4) — it is neither a pass nor a fail. Built-in adapters reach a service through its declared endpoints, published on the host's loopback (threat model B4); a URL naming another port cannot be reached and is refused rather than guessed. Retries with backoff apply before the error is final.",
		Next:       "podaro status <instance> and podaro logs <instance> <service> for the product's own account; check params.url against the module's endpoints; re-run the checkpoint",
	},
	CodeCheckpointTimeout: {
		Code:       CodeCheckpointTimeout,
		Title:      "checkpoint attempt timed out",
		Cause:      "an attempt exceeded the checkpoint's timeout (default 30s) on every retry",
		Background: "timeout bounds each attempt and retries (default 3, backoff 5s) space them (spec 0001 §2). A product that answers only after the budget is still an error result: eventual consistency is the medium, but the checkpoint says how long it is willing to wait.",
		Next:       "raise timeout or retries on the checkpoint if the product is legitimately slow; otherwise podaro logs <instance> <service>",
	},
	CodeAdapterUnavailable: {
		Code:       CodeAdapterUnavailable,
		Title:      "adapter or generator not available in this release",
		Cause:      "the checkpoint's adapter, or the seed's generator, is a name this engine cannot run: neither a built-in of the frozen registry nor an alias a composed module declares",
		Background: "Spec 0001 §3 and spec 0003 §4 freeze the names; the engine grew into them step by step — plan S6 shipped http, container, attest, exec, http-requests and web-logs. The six adapters and two generators plan S8 added for the lab the owner retired on 2026-09-23 left with it (the reconciliation plan's R2); validation refuses their names as retired, with PDR-E106, before anything runs. What is left for this code is a name that is neither a built-in nor a module alias, and an exec checkpoint on an engine with no extension runner wired. A checkpoint on such an adapter evaluates to status error, never to a guessed pass or fail.",
		Next:       "check the adapter's spelling against spec 0001 §3, or declare the module whose alias it is (spec 0003 §10)",
	},
	CodeCheckpointNotFound: {
		Code:  CodeCheckpointNotFound,
		Title: "no such checkpoint",
		Cause: "the instance's template and playbooks declare no checkpoint of that id",
		Next:  "GET /instances/<name>/checkpoints lists every id with its class",
	},
	CodeSeedFailed: {
		Code:       CodeSeedFailed,
		Title:      "seed failed",
		Cause:      "the generator could not produce or deliver its payload: the target service refused it, was unreachable, or the seed names no delivery target",
		Background: "Seeds are named deterministic injections (spec 0003 §4): the payload identity derives from the engine's seed_value (Spec 0002 §5), so a re-run sends the same thing. Built-in generators deliver over the target service's declared endpoints on the host's loopback; exec generators run as Spec 0002 containers on the instance network.",
		Next:       "read the cause; podaro logs <instance> <service> for the receiving product; podaro seed <instance> <seed> to run it again (safe by contract)",
	},
	CodeSeedNotFound: {
		Code:  CodeSeedNotFound,
		Title: "no such seed",
		Cause: "the instance's template declares no seed of that name",
		Next:  "podaro lab plan <template> lists the seeds",
	},
	CodeProgressRefused: {
		Code:       CodeProgressRefused,
		Title:      "playbook progress write refused",
		Cause:      "the write names a step the playbook does not have, a status that is not pass|fail|attested|skipped, or a pass/fail/attested that no checkpoint result backs",
		Background: "Progress statuses come only from checkpoint results or an explicit skip (spec 0001 §8): the console may never write a pass without a result behind it, so the engine checks each claimed status against the step's checkpoint's latest result.",
		Next:       "run the step's checkpoint (POST …/checkpoints/<id>/run) or attest it, then write the progress the result supports",
	},
	CodePlaybookNotFound: {
		Code:  CodePlaybookNotFound,
		Title: "no such playbook",
		Cause: "the instance's template has no playbook of that name",
		Next:  "GET /instances/<name>/playbooks lists them",
	},
	CodeSecretNotFound: {
		Code:  CodeSecretNotFound,
		Title: "no such secret",
		Cause: "the instance declares no secret of that name (template and composed modules)",
		Next:  "GET /instances/<name>/secrets lists names and kinds — never values",
	},
	CodeEvidenceNotFound: {
		Code:  CodeEvidenceNotFound,
		Title: "no such evidence entry",
		Cause: "the instance's journal holds no entry of that id",
		Next:  "GET /instances/<name>/evidence lists the journal",
	},
	CodeAttestRefused: {
		Code:       CodeAttestRefused,
		Title:      "attestation refused",
		Cause:      "the checkpoint is not an attest checkpoint",
		Background: "Only adapter: attest records a human confirmation (◇, never upgraded to a machine pass — spec 0001 §3). Every other adapter is judged by querying the product.",
		Next:       "POST …/checkpoints/<id>/run to evaluate it against the product",
	},
	CodeBaselineFailed: {
		Code:       CodeBaselineFailed,
		Title:      "instance did not reach ready: a baseline checkpoint failed",
		Cause:      "one or more baseline checkpoints of severity gate did not pass after their retries",
		Background: "Ready means verified (User Manual §2): baselines are the infrastructure truths that gate the ladder's verified and ready rungs (spec 0001 §1, §7). The containers are running and the ladder stops at seeded; objectives never block ready. The job's evidence pointer names the failing results.",
		Next:       "podaro verify <instance> after the product settles · podaro logs <instance> <service> · podaro up again to resume (the create re-verifies)",
	},
	CodeSecretStoreUnreadable: {
		Code:       CodeSecretStoreUnreadable,
		Title:      "the instance's secret store cannot be read; the operation was refused",
		Cause:      "the secrets directory of the instance, or one of its files, could not be read — permissions changed, the path replaced, an I/O error — or the store holds no value for a secret once generated for the instance — a history the state database keeps until destroy — because a directory was removed or a file deleted",
		Background: "Everything the engine persists or logs about an instance — checkpoint messages and observed values, exec and init output, seed reports, job journal lines, failure records — passes the redaction filter built from every value in the instance's secret store (threat model B9, invariant 6). A filter that cannot be built, or that lacks a value the running containers were configured with, is not an empty filter: the engine refuses the operation rather than record text the filter never saw, and the failure it records is this one, the operation's own error withheld. A destroy — the remedy — proceeds with the filter that can be built: its journal carries step names, object names and verb-only runtime errors, never product output.",
		Next:       "an unreadable store: restore instances/<name>/secrets under the state directory — a directory the engine's user owns, mode 0700, one 0600 file per secret — then re-run · a value that is gone cannot be regenerated in place (the containers were configured with it): podaro destroy <name>, then up again · podaro doctor",
	},
	CodeExplainUnknown: {
		Code:       CodeExplainUnknown,
		Title:      "no such error code",
		Cause:      "the code asked about is not one this release can emit; every code Podaro emits has an entry in the registry embedded in this binary, and that one has none",
		Background: "The registry is maintained in the same change as the code that emits it, so a code with no entry is either from another release or a typo. `podaro explain --list` prints every code this binary knows.",
		Next:       "podaro explain --list",
	},

	CodeExecPull: {
		Code:       CodeExecPull,
		Title:      "exec image pull failed",
		Cause:      "the extension image named by a checkpoint or seed could not be pulled at create or plan time",
		Background: "Spec 0002 §2: image pulls happen at create/plan time through normal channels, never at run time — an extension container has no egress to pull anything itself. The cause carries the registry's own message.",
		Next:       "check the image reference and digest, registry access, and podaro doctor; then re-run",
	},
	CodeExecExit: {
		Code:       CodeExecExit,
		Title:      "exec container exited non-zero",
		Cause:      "the extension container ended with a non-zero exit code",
		Background: "Spec 0002 §4: exit code 0 means 'I ran' — a failing assertion exits 0 with status fail. A non-zero exit is the adapter itself failing (a crash, a missing dependency), so the checkpoint's status is error and the redaction-filtered stderr excerpt is attached to evidence.",
		Next:       "read the stderr excerpt in the evidence entry; fix the adapter image; re-run the checkpoint",
	},
	CodeExecTimeout: {
		Code:       CodeExecTimeout,
		Title:      "exec container exceeded its timeout",
		Cause:      "the extension container did not finish within the checkpoint or seed timeout",
		Background: "Spec 0002 §2: wall-clock is bounded by the checkpoint/seed timeout (default 30s); the container is removed when it expires. The result records elapsed versus budget.",
		Next:       "raise the timeout if the judgment legitimately takes longer; otherwise fix the adapter's wait loop",
	},
	CodeExecOutput: {
		Code:       CodeExecOutput,
		Title:      "exec container output is not contract JSON",
		Cause:      "stdout was not one JSON object carrying contract podaro.dev/exec/v1 with a valid status, or the 64 KiB cap cut it — what followed the cap is unknown, so the kept prefix is no verdict",
		Background: "Spec 0002 §2, §4 and §7: stdout is the contract and nothing else; chatter goes to stderr. The result names the fault's kind and byte offset and never quotes stdout itself — an output that is not the contract may hold anything, a secret in an escaped form the redaction filter cannot see included; the redaction-filtered stderr excerpt in the evidence entry is where the author reads what was printed instead.",
		Next:       "print only the verdict JSON on stdout (status pass|fail for checkpoints, ok for seeds); move diagnostics to stderr",
	},
	CodeExecRoot: {
		Code:       CodeExecRoot,
		Title:      "exec image refused: it would run as root",
		Cause:      "the image declares no USER, USER root, or USER 0 — or its effective uid could not be resolved",
		Background: "Spec 0002 §2, the identity wall: extension containers must run as non-root; the engine refuses images whose effective UID is 0 before anything runs, at create (the image is inspected once pulled). Read-only rootfs, dropped capabilities, and the 64 MiB /tmp tmpfs apply to the ones that pass.",
		Next:       "add USER <non-root uid> to the adapter image's Containerfile and re-pin its digest",
	},
}

// Lookup returns the registry entry for a code.
func Lookup(code string) (Entry, bool) {
	e, ok := registry[code]
	return e, ok
}

// Codes returns all registered codes, sorted.
func Codes() []string {
	out := make([]string, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// NormalizeCode reads a code the way an operator types it: any case, with
// or without the PDR prefix, and with the separator either way round —
// `pdr-e503`, `E503` and `503` all name PDR-E503. What is not a code is
// returned unchanged, so the caller reports it as typed.
func NormalizeCode(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "PDR-")
	t = strings.TrimPrefix(t, "PDR")
	t = strings.TrimPrefix(t, "-")
	if t == "" {
		return strings.TrimSpace(s)
	}
	if t[0] >= '0' && t[0] <= '9' {
		// A bare number names an error, the family that has them: W codes
		// are warnings and are always written out.
		t = "E" + t
	}
	return "PDR-" + t
}

// Near names the registered codes closest to one that is not registered —
// the same family, or a neighbouring number — so a typo answers with the
// code the operator meant rather than only with a refusal.
func Near(code string) []string {
	if !strings.HasPrefix(code, "PDR-") || len(code) < 6 {
		return nil
	}
	want := code[4:]
	var out []string
	for _, c := range Codes() {
		got := c[4:]
		if len(got) != len(want) || got[0] != want[0] {
			continue
		}
		diff := 0
		for i := range got {
			if got[i] != want[i] {
				diff++
			}
		}
		if diff == 1 {
			out = append(out, c)
		}
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}
