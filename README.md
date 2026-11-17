<div align="center">

<img src="docs/yap-icon.png" width="128" alt="Yap app icon: a speech bubble with a face whose mouth is a waveform">

# Yap

**Talk to your Mac. It talks back.**

Press a shortcut and talk: your words type themselves wherever the cursor is. Highlight anything and hear it read aloud in a natural voice. Give your AI agents the same voice and ears. All of it runs on your Mac, free and open source.

[Install](#install) · [How you use it](#how-you-use-it) · [Agents](#give-your-agents-a-voice) · [Privacy](#privacy)

https://github.com/user-attachments/assets/8fae0d41-6e23-4b7c-8de5-03618614a30b

</div>

## Hardening evaluation

This checkout is for source evaluation. Do not install it on a primary Mac or bypass Gatekeeper. The isolated workflow, supported features, and release gates are documented in [Hardening evaluation](docs/hardening/EVALUATION.md).

## How you use it

| | Press | What happens |
|---|---|---|
| **Ears** | **⌘⇧D**, talk, **⌘⇧D** | A live preview floats while you talk. The accurate transcript is pasted at your cursor, in any app. |
| **Voice** | Select text, **⌘⇧R** | It reads aloud as it synthesizes. Pause, stop and change speed from the menu bar. |
| **Services** | Right-click ▸ **Read with Yap** | Same as Voice, from any app's context menu. |

<p align="center"><img src="docs/yap-ui.png" width="820" alt="Yap's menu-bar popover (Ears and Voice) next to its Settings window"></p>

Both shortcuts can be any chord, including a modifier-only one like ⌥⌘ held and released.

- **Dictation** runs NVIDIA Parakeet on the Apple Neural Engine, with a fast streaming model for the live preview and a more accurate model for the final text. Use English or multilingual mode. Settings ▸ History can save up to 500 dictations and 500 reads when you enable recording.
- **Kokoro** provides 54 voices in 8 languages on CPU. Pocket TTS and voice cloning are disabled in the evaluation.
- **Cleanup before it speaks.** Markdown, code blocks, citations and URLs are stripped so you hear the words, not the punctuation.

Yap is a free alternative to the dictation features of [Wispr Flow Pro](https://wisprflow.ai/pricing), [Superwhisper Pro](https://ai.superwhisper.com/) and [MacWhisper Pro](https://goodsnooze.gumroad.com/l/macwhisper), and it reads aloud too.

## Give your agents a voice

Coding with an agent is mostly typing prompts and reading long replies. Yap removes both:

1. **Talk your prompt** into Claude Code, Codex or Cursor with ⌘⇧D.
2. **Listen to the answer.** Paste the block below into your agent's `AGENTS.md` or `CLAUDE.md`. Every reply then ends with a short spoken summary; select it and press ⌘⇧R.

```md
## 🔊 Speak to me
End every reply longer than a line with a spoken block I will listen to through text-to-speech. Its header says whether I have to act:

- `## 🔊 Speak to me · no input needed`: where the work stands and when it will be done.
- `## 🔊 Speak to me · decision needed`: what you need from me, what I need to understand to decide, the options counted out in words with what each costs, and which you would pick. One ask per reply.

Inside the block: plain spoken sentences only. No markdown, code, tables, links or symbols, because a voice reads them out literally. Spell out numbers and flags in words. Skip the block when the task asks for an exact machine format, like JSON, a diff or a commit message.
```

The same block, plus a simpler version, is in **Settings ▸ Agents** with a Copy button and a spoken example.

![A "Speak to me" section an agent wrote, ready to read aloud](docs/speak-to-me.png)

### Let agents speak and listen on their own

Yap offers an opt-in local API for agents, scripts, and desktop companions. The API and microphone access through it have separate switches in Settings ▸ Agents.

```bash
ln -s /Applications/Yap.app/Contents/Resources/bin/yap /usr/local/bin/yap   # once
yap say "The build finished and all tests pass."
yap listen          # opens dictation, prints what you said
```

It is HTTP over a private socket in `~/Library/Application Support/Yap`, so no web page and no other user can reach it. Listening is off until you turn it on in **Settings ▸ Agents**, because it lets a program you run use Yap's microphone; the dictation window always shows while it listens. Every endpoint, with curl and Python examples: [docs/AGENT-API.md](docs/AGENT-API.md).

## Privacy

Speech synthesis and dictation run locally. **Accessibility** lets Yap read a selection and paste a transcript. **Microphone** feeds dictation. To read without granting Accessibility, set **Read source** to Clipboard and copy text yourself.

Launch-time loading for Voice and Dictation is opt-in and can download missing models. Update checks are also opt-in and run at launch, at most once per 24 hours after a successful check. See [Privacy and permissions](docs/PRIVACY.md).

> In terminals like iTerm, which don't expose their selection, **Auto** read source falls back to your clipboard. Highlighting there replaces what you'd copied, and pressing Read with nothing selected speaks the clipboard. Want strict selection only? Set **Read source** to Selected text.

## How it's built

```
SwiftUI menu-bar app ──pinned HTTPS──> local FastAPI sidecar ──> Kokoro (ONNX, CPU)
  hotkeys · capture · cleanup · player
  mic ──> FluidAudio · Parakeet (CoreML, Apple Neural Engine)   ← dictation, in-app
```

The voice runs in a local Python sidecar on `127.0.0.1`; dictation runs inside the app. Module map: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

MIT. Kokoro weights Apache-2.0 (hexgrad/Kokoro-82M). Pocket TTS by [Kyutai](https://github.com/kyutai-labs/pocket-tts), CC-BY-4.0; Yap serves a byte-identical mirror of the cloning weights so no account is needed. Starter voices from CMU ARCTIC. Dictation uses [FluidAudio](https://github.com/FluidInference/FluidAudio) (Apache-2.0) running NVIDIA Parakeet. Clone only voices you have rights to.
