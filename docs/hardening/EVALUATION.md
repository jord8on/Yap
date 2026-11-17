# Yap hardening evaluation

This PR is for source-only preparation and review. Do not install or launch its
build on a primary Mac. Preserve quarantine and normal Gatekeeper settings.
Do not override platform security, publish an artifact, merge, or notarize in
this PR. A passing source check or development build does not authorize
installation or distribution.

## Frozen inputs

| Input | Commit |
| --- | --- |
| Upstream source baseline | `6b9375f99f0ece993bedbf10cbbe4662c1c0f02b` |
| Historical patch donor | `3ffd2a9a0e1f11e7bb9be7e669232731ff636c19` |

The evaluation selectively ports source changes. It retains the upstream
`backend/requirements*.txt`, `scripts/python_pin.sh`, and
`app/Package.resolved` byte for byte. The regular bundled runtime uses the
pinned CPython asset and the default hash lock with binary-only installs.
The Pocket lock remains preserved, but the deferred engine is not installed by the focused evaluation. The exact protected file identities are in [frozen-inputs.json](frozen-inputs.json).

## Protection in scope

- The speech sidecar uses pinned HTTPS on loopback, a private local certificate
  and bearer token, and a nonce-bound HMAC proof. The client requires the pin
  on the connection carrying bearer credentials or speech text. Missing
  credentials, unverified listeners, and browser-originated requests fail
  closed. Process names alone do not authorize adoption or termination.
- Packaging retains quarantine metadata. Normal signing requires a valid
  signature before promoting a staged app to the build output. The isolated
  evaluation signs explicitly with an ad-hoc development signature. Packaging
  and the embedded Python launcher suppress bytecode writes into the bundle.
- Kokoro and in-app dictation are in scope. Pocket TTS and voice cloning are
  disabled for this evaluation, with existing files retained. History
  recording, the agent socket, agent listening, automatic update checks,
  dictation, and launch-time loading of the reading model require opt-in.
  The upgrade resets these switches once. When enabled, history stores full
  text locally and agents running as the same user can use the local socket.
- Kokoro retains its checked model digests. Dictation model requests use the
  public registry without ambient registry overrides or credentials. The
  review still needs the exact dictation model revisions, file digests, and
  observed network destinations.

This protects against specified local listener and origin failures. A process
already running as the same macOS user may be able to access the private
identity files. File permissions and pinned TLS do not isolate applications
that share a user account.

## Evidence

The [source workflow](../../.github/workflows/security.yml) runs on every PR
on hosted Ubuntu. It checks whitespace, Bash syntax, and read-only source
guards, including in-memory mutations expected to fail the guards. It records
the tested merge commit, PR head and base, runner and toolchain, lock digests,
and check outcome.

The [macOS workflow](../../.github/workflows/evaluation.yml) is explicit opt-in.
For this unmerged PR, the repository owner can apply `run-isolated-evaluation`
to start a disposable GitHub-hosted macOS job for the PR's exact head SHA.
It runs only on that label-add event, not automatically after later pushes.
Remove/reapply the label to authorize a new head. The label has not been applied
as part of preparation. The workflow also supports a dispatch input for future
use when GitHub makes it dispatchable; no default-branch change is required for
the PR label path. The read-only job checks out and records the selected SHA,
compares locks with inputs, builds a development bundle, and runs focused Python
and Swift TLS and privacy tests. It also exercises the embedded Python sidecar
over HTTPS with a disposable identity and checks the development bundle
seal after the probe. Test tools are pinned separately from shipped runtime
dependencies. Receipts include the tested SHA, OS, toolchain, lock digests,
observed executable digests, logs and outcomes. Both workflows attempt
receipt upload after failures. The macOS workflow uploads receipts only.

Development executable digests identify files produced by that run. Audit
coverage, build reproducibility, release provenance, and Gatekeeper acceptance
require separate evidence. No workflow run is claimed here. The automatic
source checks do not run the existing dependency, code, or secret scanners.

## Acceptance checklist

| Gate | Required evidence |
| --- | --- |
| G01 | Record the exact evaluated commit, base, donor, and lock digests. Confirm the scoped PR preserves the upstream locks. |
| G02 | Record the exact Swift dependency version/revision and source-native targets. This is source identity, not binary provenance. |
| G03 | **Code work.** Integrate selected protections onto the frozen upstream, leaving the old CI branch untouched. Review the composed diff and exact-SHA tests, including privacy migration and deferred feature policy. |
| G04 | **Code work.** Confirm token read/create errors prevent startup; wrong or missing credentials fail; listener impersonation fails. Require negative auth/TLS tests for the new candidate. |
| G05 | **Code work.** Confirm no automatic quarantine removal or platform-security override in app, scripts or installer, with static review and isolated runtime evidence. |
| G06 | Inventory all native executables, Mach-O slices, libraries, and links in the actual distribution. Record source and build provenance and reconcile it with a machine-readable SBOM. |
| G07 | Run a fresh advisory scan for the exact distribution and both current dependency locks. Record scanner versions, data timestamps, findings and dispositions. Keep the separate code and secret scan evidence. |
| G08 | Pin or verify model revisions and file digests. Capture runtime egress in an isolated environment for first launch, model downloads, idle, and speech/dictation workflows. Investigate unexpected destinations or payloads. |
| G09 | On an isolated interactive Mac, verify history opt-in, deletion, existing-data handling, and agent Settings, socket, listening and disable behavior. |
| G10 | On an isolated interactive Mac, verify Microphone and Accessibility prompts, consent, refusal and revocation, capture indicators, and clipboard restoration. |
| G11 | Verify the seal of the exact packaged app and mounted DMG before and after representative use. Verify that imports, restarts and supported model flows do not mutate the sealed bundle. |
| G12 | Sign the exact distribution with Developer ID and hardened runtime, notarize and staple it in a separate release task, and verify installation with normal Gatekeeper settings and quarantine intact. |
| G13 | Have an independent reviewer inspect the exact distribution and the G01–G12 evidence before authorizing release. Include any external cask or other installer in the review. |

G03–G05 are implementation and review gates. G06–G13 remain release gates,
including when the isolated development workflow succeeds.

## Review disposition and remaining implementation limitation

The separate source review identified an undispatchable branch-only workflow,
unrelated child credentials/trust overrides, and a legacy test that could touch
real application state. Preparation adds the owner-only PR label trigger, a
minimal child-environment allowlist with fixed system PATH, and a private test
identity with restored globals. Existing user-owned regular history files are
restricted to mode 0600 before loading without rewriting their bytes; symlinks
are refused. Their new Swift regressions still require isolated macOS execution.

**Open P2 availability limitation:** interruption between first creation of the
TLS key and certificate can leave a partial pair. Startup intentionally refuses
that pair rather than silently deleting or rotating identity material. Atomic
pair publication/recovery remains an explicit review item before daily use.
Do not repair this by disabling authentication, TLS, or platform checks. It does
not make an untested build release-ready.
