# Privacy & permissions

This page describes the hardening evaluation's intended behavior. Runtime
verification and release acceptance are tracked in the [evaluation checklist](hardening/EVALUATION.md).

## The short version

- Kokoro synthesizes speech locally. Dictation is transcribed on the Apple Neural
  Engine using Parakeet and Nemotron models.
- Pocket TTS and voice cloning are disabled in the evaluation. Existing engine
  files and recordings stay on disk.
- Dictation, loading the reading model at launch, history recording, the agent
  API, agent listening, and automatic update checks are off by default. The
  upgrade resets these switches once. Choices made after the upgrade persist.

## What goes over the network

Yap's intended outbound requests are model downloads and optional update
checks. Model requests can expose ordinary connection metadata to their hosts.
Full runtime egress verification is pending.

**At launch, without a click:**

- **The Kokoro voice** (~340 MB), when **Reading aloud (voice)** and **Load the
  reading model at launch** are on and Kokoro's files are missing. Both files
  are checked against pinned SHA-256 hashes.
- **Dictation models.** With Dictation enabled, Yap loads the selected
  model pair at launch and downloads any missing files. English uses Parakeet
  Flash for streaming and Parakeet TDT v2 for the final pass; multilingual uses
  Nemotron and Parakeet TDT v3. They are cached in
  `~/Library/Application Support/FluidAudio/Models`. If you delete them in
  Settings ▸ Models, they download again at the next launch. Turn off
  **Dictation (ears)** in Settings ▸ General to stop this.
- **Automatic update checks**, at launch when enabled and at least 24 hours have
  passed since the last successful check. See [below](#the-update-check-optional).

**When you ask for it:**

- The Kokoro model (~340 MB), from a read request or **Download model** in
  Settings ▸ Models.
- Dictation models, when you enable Dictation, switch its model while enabled,
  or request a download from Settings ▸ Models.

Kokoro's sidecar listens on loopback HTTPS with a private local certificate
and bearer token. Full dictation model revision and digest checks remain part
of the model egress acceptance gate.

## The two permissions Yap asks for

Yap has two jobs: read the text you select aloud, and type back what you say.
Each needs exactly one grant, and you can use either half without the other.

### Accessibility (reading a selection, and typing a transcript back)

macOS protects three capabilities behind it:

1. **Reading the selected text of another app.** macOS only lets a *trusted*
   process query another app's UI via the Accessibility API (`AXUIElement` →
   `kAXSelectedTextAttribute`). Without the grant, that call returns nothing.

2. **Simulating ⌘C for the clipboard fallback.** When an app doesn't expose its
   selection over the Accessibility API, Yap falls back to copying: it posts
   a synthetic ⌘C (`CGEvent`), reads the result, and **restores your previous
   clipboard**. Posting a synthetic keystroke also requires the same trust.

3. **Simulating ⌘V to paste a transcript at your cursor.** Dictation puts the
   finished text on the pasteboard, posts a synthetic ⌘V, then **restores your
   previous clipboard**: the same mechanism and the same restore as the copy
   path ([`TextInsert.swift`](../app/Sources/Yap/TextInsert.swift)).

These are the *only* reasons. The grant is broad on paper ("control your
computer") because that's the single switch macOS offers — but what Yap
actually does with it is narrow and visible in
[`TextCapture.swift`](../app/Sources/Yap/TextCapture.swift).

### Microphone (dictation)

Press ⌘⇧D to start dictation. Capture begins once the model is ready and
microphone permission is granted. Press again to stop; Yap allows a 0.6-second
finishing window to catch the last word and mic buffers.
The HUD stays red and says “Finishing…” during that window. The mic then closes
before the final transcript is inserted. Audio is processed by a local Parakeet
or Nemotron model on the Apple Neural Engine; it is
**never written to disk and never leaves the machine**. There is no sidecar,
and the only network use is downloading its models
([`Dictation.swift`](../app/Sources/Yap/Dictation.swift)). Don't dictate? Don't
grant it. The read-aloud half works without it.

## The agent API (a local socket)

After you enable the agent API, other programs running as your user can ask
Yap to speak, or to listen if you grant that separately, through a Unix
socket at `~/Library/Application Support/Yap/yap.sock`
([details](AGENT-API.md)). It is a file, not a network port: no connection leaves
your Mac, web pages cannot reach it, and other macOS users cannot open it (it is
mode `0600`). The API adds no outbound network call.

Other programs running as your user can use the enabled socket. Agent listening
has a separate opt-in because it uses Yap's Microphone grant. The dictation HUD
shows during capture and the transcript goes to the caller. Inserting it at
the cursor requires a separate request. Disabling the API removes the socket.

## Spoken and dictated history

Settings ▸ History controls recording and deletion. Enabling recording saves
full text locally in a plaintext history file with user-only permissions.
Turning recording off stops new entries. Existing entries stay available until
you delete them or clear their list.

## What Yap does NOT do

- Hotkeys use registered shortcuts and a modifier-only global monitor. The
  Settings shortcut recorder observes key presses locally while recording a
  chord.
- No always-on listening. The mic records only during a dictation session,
  including the 0.6-second finishing window after you press stop. A program using
  the [agent API](AGENT-API.md) starts the same session, with the same HUD, and
  only once you have turned that on.
- No screen reading or screenshots.
- No background scraping. Nothing is captured unless you trigger it.
- No clipboard hijacking. The fallback restores whatever was on your clipboard.

## The update check (optional)

When enabled, Yap checks GitHub at launch for the latest release if at least 24
hours have passed since its last successful check. If Yap stays open, no further
automatic check runs until its next launch. It's a single unauthenticated GET to
the public releases API
(`api.github.com/repos/latent-variable/Yap/releases/latest`) — no account, no
identifier, no usage data sent. Yap just receives the latest version number,
compares it to the running build, and shows a banner if a newer one exists. It
links to the release page without downloading or installing an update.

Off on a fresh profile. **Settings ▸ General ▸ Updates** controls automatic
checks separately from launch model downloads. [`UpdateChecker.swift`](../app/Sources/Yap/UpdateChecker.swift)

## Read source modes and your clipboard

Yap ships with **Read source → Selected text** and **Capture method → Clipboard**.
For a selected-text read, Yap saves the pasteboard, posts a synthetic ⌘C to read
the selection, then restores the saved contents. This needs Accessibility
permission to post the key event. Set **Capture method → Accessibility** to read
a live selection through the Accessibility API without using the clipboard.

**Auto** is opt-in (Settings ▸ Permissions ▸ Read source). It tries to read the live
selection using the selected Capture method, then falls back to the clipboard
when no text is returned. Some apps (iTerm and other terminals) don't expose
their selection to the Accessibility API and block synthetic ⌘C, so Yap reads
the clipboard instead. If you turn Auto on, two things are worth knowing:

- **Yap restores the pasteboard after synthetic ⌘C.** The Auto fallback only
  reads the clipboard.
- **The one clipboard change you'll see in a terminal is its own doing.** iTerm's
  copy-on-select feature replaces your clipboard the moment you highlight text.
  That's the terminal, not Yap. So after reading in iTerm, your previous
  clipboard contents are gone, replaced by what you selected.

It's a small quirk you get used to.

**The menu's play button reads your clipboard in every mode.** Pressing it with
nothing selected reads whatever you last copied, again on every press. That is
the point of the button. With Accessibility granted it tries your selection
first, even in Clipboard mode (the same ⌘C round-trip, clipboard restored). The
shortcut keeps the mode you chose.

## The no-permission option

You can read aloud without granting anything: set **Read source → Clipboard**.
Then you copy text yourself (⌘C) and press the shortcut; Yap reads the
clipboard. Reading your own clipboard is unrestricted, so no permission is
involved.

## The stale-grant gotcha (and the fix)

macOS ties an Accessibility grant to the app's code identity. An identity
change can make an existing grant stop matching the running app. The checks
below are for an approved isolated test environment outside this source-only
PR.

Fix it cleanly:

1. System Settings ▸ Privacy & Security ▸ Accessibility.
2. Select **Yap**, click **−** to remove it.
3. Relaunch Yap and grant again (fresh entry, bound to the current binary).

Permanent fix — run once:

```bash
bash scripts/setup_signing.sh      # creates a stable self-signed identity
bash scripts/build_app.sh          # now signs with it
```

After that the code identity is stable across rebuilds, so a single grant
persists through every future update.

## Verify it yourself

```bash
# what the app sees for capture, including trust state:
/Applications/Yap.app/Contents/MacOS/Yap --diag

# runtime log of every capture attempt:
cat ~/Library/Application\ Support/Yap/yap.log
```

The log stays on this Mac. Per capture it records which app was in front (its
bundle id, e.g. `com.googlecode.iterm2`), whether the clipboard changed since the
last press, how long the capture took and how many characters it got. Never the
text itself.
