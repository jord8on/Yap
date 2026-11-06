# Yap security review and release acceptance gates

This is a checklist for security-focused development. Passing it increases
confidence; it is not a guarantee that an app is free of malware or vulnerabilities.

## Proposed fixes (review/merge status is separate from code completion)

- [ ] Local backend verifies its identity before the first bearer credential or
  text request, and on subsequent calls; failing to load the token rejects work.
- [ ] Token creation and storage reject symlinks, unsafe ownership and permissions.
- [ ] Other programs' access to the local agent socket is disabled by default,
  unless the user explicitly opts in.
- [ ] Storing complete speech and dictation history is opt-in; new history files
  have restrictive local permissions and existing files can be cleared.
- [ ] The bundled Python interpreter comes from an immutable release asset
  verified against a reviewed SHA-256.
- [ ] Every Python dependency and transitive dependency is resolved to a
  reviewed, platform-specific, hash-verified lock (including optional Pocket).
- [ ] A machine-readable SBOM and vulnerability scan are produced for each build.

## Required tests

- [ ] Python backend unit tests and negative auth scenarios on an isolated runner.
- [ ] Compile the Swift app and XCTest target with the resolved dependencies.
- [ ] A fake listener on the local TTS port receives neither a Bearer token nor
  selected text, both at initial launch and after a legitimate server exits.
- [ ] An unknown listener cannot be killed or adopted by spoofing a process name.
- [ ] Test unreadable/missing tokens, symlink traps, multiple instances, and
  backend crash/recovery.
- [ ] Verify agent socket mode, peer UID restrictions, and microphone permission
  behavior with a non-privileged local test program.
- [ ] Verify transcript history enable/disable, retention, on-disk permissions,
  deletion behavior, and existing-data migration.
- [ ] Monitor outbound network traffic from a released application on an
  isolated macOS account/VM; investigate all unexpected destinations.

## Distribution acceptance

- [ ] Use an Apple Developer ID identity and hardened runtime for **all**
  executable components and nested Python libraries.
- [ ] Produce a notarized, stapled DMG and validate the **packaged** copy.
- [ ] Remove any code and installation instructions that indiscriminately
  clear quarantine flags once notarized distribution is in place.
- [ ] Record the commit, dependency locks, toolchain, build commands, binary
  digests, and release verification steps.
- [ ] Independently inspect the exact DMG to be distributed, not just source
  or a development build.

## Known architectural limitation

The bearer token file is readable by the account running Yap. A malicious
process *already running as that same macOS user* may read the file; no HMAC
challenge can prevent that. Using a per-user Unix-domain socket with verified
peer credentials or a process-bound channel could improve local process
authentication, but is not the same as isolating applications inside one
macOS user account. The hardened client pins the private per-user TLS identity
on the connection carrying each authenticated request, removing the separate
preflight-to-request listener substitution window. A same-user process that
can read both the token and TLS private key remains outside that protection.

**Release rule:** Do not consider a patched but unsigned, untested source build
ready for a sensitive primary Mac. Keep changes in draft review until the
relevant release gates are verified and documented.
