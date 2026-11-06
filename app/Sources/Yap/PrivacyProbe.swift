import AVFoundation
import Darwin
import Foundation

/// Packaged-app privacy checks without starting a backend, loading models, or
/// requesting microphone access. Run only through scripts/ci/test-packaged-privacy.sh:
/// CFFIXED_USER_HOME alone does NOT isolate the UserDefaults domain, so the
/// wrapper gives a copied bundle a unique identifier before launching this probe.
enum PrivacyProbe {
    static func run() -> Never {
        setvbuf(stdout, nil, _IOLBF, 0)
        Task { @MainActor in exit(await Runner().run()) }
        dispatchMain()
    }

    private struct Paths {
        let root: URL
        let support: URL
        let bundleID: String
        var history: URL { support.appending(path: "Yap/history.json") }
        var socket: String { root.appending(path: "agent/yap.sock").path }
    }

    private enum ProbeError: LocalizedError {
        case refused(String)
        var errorDescription: String? {
            switch self { case .refused(let reason): return reason }
        }
    }

    private struct Check: Codable {
        let name: String
        let passed: Bool
        let detail: String
    }

    private struct Report: Codable {
        let checks: [Check]
        let failures: Int
        let microphoneAuthorizationBefore: String
        let microphoneAuthorizationAfter: String
        let notYetTested: [String]
    }

    @MainActor
    private final class Runner {
        var checks: [Check] = []
        var captureAttempted = false

        func check(_ name: String, _ passed: Bool, _ detail: String = "") {
            checks.append(Check(name: name, passed: passed, detail: detail))
            print("  \(passed ? "PASS" : "FAIL") \(name)\(detail.isEmpty ? "" : ": " + detail)")
        }

        /// Refuse before touching Prefs, migration, history, or the socket unless
        /// both filesystem and defaults isolation came from the dedicated wrapper.
        func isolatedPaths() throws -> Paths {
            let env = ProcessInfo.processInfo.environment
            let fm = FileManager.default
            guard let rootPath = env["YAP_PRIVACY_TEST_ROOT"], rootPath.hasPrefix("/"),
                  let homePath = env["CFFIXED_USER_HOME"],
                  let bundleID = env["YAP_PRIVACY_TEST_ID"],
                  bundleID.hasPrefix("dev.yap.privacyprobe."),
                  UUID(uuidString: String(bundleID.dropFirst("dev.yap.privacyprobe.".count))) != nil,
                  Bundle.main.bundleIdentifier == bundleID,
                  env["YAP_PRIVACY_SANDBOX_ACTIVE"] == "1" else {
                throw ProbeError.refused("use scripts/ci/test-packaged-privacy.sh; a unique test bundle and isolated home are required")
            }
            let root = URL(fileURLWithPath: rootPath).resolvingSymlinksInPath().standardizedFileURL
            let home = URL(fileURLWithPath: homePath).resolvingSymlinksInPath().standardizedFileURL
            let bundle = Bundle.main.bundleURL.resolvingSymlinksInPath().standardizedFileURL
            guard root.path.hasPrefix("/private/tmp/yap-privacy."),
                  home.path == root.appending(path: "home").path,
                  bundle.path == root.appending(path: "YapPrivacyProbe.app").path,
                  let support = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first,
                  support.resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(home.path + "/"),
                  (try? String(contentsOf: root.appending(path: "probe-id"), encoding: .utf8)) == bundleID else {
                throw ProbeError.refused("test bundle, marker, and Application Support must resolve inside the private probe directory")
            }
            var st = stat()
            guard lstat(root.path, &st) == 0, st.st_uid == getuid(),
                  st.st_mode & S_IFMT == S_IFDIR, st.st_mode & 0o077 == 0 else {
                throw ProbeError.refused("probe directory must be owned by this user and inaccessible to other users")
            }
            if let pw = getpwuid(getuid()), let real = String(validatingCString: pw.pointee.pw_dir),
               URL(fileURLWithPath: real).resolvingSymlinksInPath().standardizedFileURL.path == home.path {
                throw ProbeError.refused("CFFIXED_USER_HOME must not be the user's real home")
            }
            guard env["YAP_HISTORY_FILE"] == nil, HistoryStore.probeFileURL == nil,
                  !fm.fileExists(atPath: support.appending(path: "Yap").path),
                  !fm.fileExists(atPath: support.appending(path: "Parley").path) else {
                throw ProbeError.refused("history overrides or existing app data would invalidate fresh-install privacy checks")
            }
            guard (UserDefaults.standard.persistentDomain(forName: bundleID) ?? [:]).isEmpty else {
                throw ProbeError.refused("the unique test preference domain already contains data")
            }
            return Paths(root: root, support: support, bundleID: bundleID)
        }

        func until(_ seconds: Double = 3, _ condition: () -> Bool) async -> Bool {
            let deadline = Date().addingTimeInterval(seconds)
            while Date() < deadline {
                if condition() { return true }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            return condition()
        }

        struct Reply { let status: Int; let json: [String: Any]; let raw: String }

        func request(_ socket: String, _ method: String, _ path: String) async -> Reply {
            let body = method == "POST" ? "{}" : ""
            let request = "\(method) \(path) HTTP/1.1\r\nHost: yap\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
            let raw = await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
                DispatchQueue.global().async {
                    continuation.resume(returning: AgentSelftest.raw(socket, request, timeout: 3))
                }
            }
            let parts = raw.components(separatedBy: "\r\n\r\n")
            let bodyData = Data(parts.dropFirst().joined(separator: "\r\n\r\n").utf8)
            let json = (try? JSONSerialization.jsonObject(with: bodyData)) as? [String: Any] ?? [:]
            return Reply(status: AgentSelftest.status(raw), json: json, raw: raw)
        }

        func errorCode(_ reply: Reply) -> String? {
            reply.json["code"] as? String
        }

        func storedTexts(_ url: URL, _ kind: String) -> [String]? {
            guard let data = try? Data(contentsOf: url),
                  let snapshot = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let entries = snapshot[kind] as? [[String: Any]] else { return nil }
            return entries.compactMap { $0["text"] as? String }
        }

        func microphoneStatus() -> String {
            switch AVCaptureDevice.authorizationStatus(for: .audio) {
            case .notDetermined: return "notDetermined"
            case .restricted: return "restricted"
            case .denied: return "denied"
            case .authorized: return "authorized"
            @unknown default: return "unknown"
            }
        }

        func run() async -> Int32 {
            let paths: Paths
            do { paths = try isolatedPaths() }
            catch { print("REFUSED: \(error.localizedDescription)"); return 2 }

            let fm = FileManager.default
            let defaults = UserDefaults.standard
            // Skip only legacy preference import: never read the real Parley
            // domain into this otherwise fresh, uniquely named test domain.
            defaults.set(true, forKey: "didMigrateFromParley")
            defer {
                defaults.removePersistentDomain(forName: paths.bundleID)
                defaults.synchronize()
            }
            let microphoneBefore = microphoneStatus()
            print("Packaged privacy probe: \(paths.bundleID)")
            print("Microphone authorization: \(microphoneBefore) (read only; no permission request)")
            let prefs = Prefs.shared
            check("fresh defaults: agent API off", !prefs.agentAPIEnabled)
            check("fresh defaults: delegated listening off", !prefs.agentListenEnabled)
            check("fresh defaults: history collection off", !prefs.historyEnabled)

            // Set unrelated execution gates BEFORE creating the real controllers.
            // No app/dictation bootstrap is called, so neither models, hotkeys,
            // update checks, nor a backend start. The dictation master switch is
            // a second safety barrier if the separate delegation guard regresses.
            prefs.voiceEnabled = false
            prefs.dictationEnabled = false
            prefs.autoUpdateCheck = false
            prefs.autoLoadHD = false
            prefs.muteAllSounds = true
            prefs.volume = 0
            let state = AppState.shared
            let dictation = DictationController.shared
            dictation.headless = true
            dictation.simulatedCapture = { [weak self] _ in
                self?.captureAttempted = true
                throw CancellationError()
            }
            let controller = AgentAPIController(state: state, dictation: dictation, prefs: prefs,
                                                socketPath: paths.socket)
            defer { controller.stop() }
            controller.bootstrap()
            try? await Task.sleep(nanoseconds: 150_000_000)
            check("default-off bootstrap leaves no agent socket", !fm.fileExists(atPath: paths.socket))

            prefs.agentAPIEnabled = true
            let socketStarted = await until { fm.fileExists(atPath: paths.socket) }
            check("opting in starts the real agent socket", socketStarted)
            check("agent socket permissions are 0600", AgentSelftest.mode(paths.socket) == 0o600)
            let status = await request(paths.socket, "GET", "/status")
            check("enabled agent API serves its status route", status.status == 200)
            check("status reports delegated listening denied", status.json["listen_allowed"] as? Bool == false)
            let denied = await request(paths.socket, "POST", "/listen")
            check("API opt-in alone cannot delegate the microphone",
                  denied.status == 403 && errorCode(denied) == "listen_disabled")

            // Exercise the real second toggle while dictation stays disabled:
            // this reaches its independent denial, never model/microphone startup.
            prefs.agentListenEnabled = true
            let masterDenied = await request(paths.socket, "POST", "/listen")
            check("delegation opt-in still honors disabled dictation",
                  masterDenied.status == 403 && errorCode(masterDenied) == "dictation_disabled")
            prefs.agentListenEnabled = false
            let revoked = await request(paths.socket, "POST", "/listen")
            check("revoking delegation immediately restores listen denial",
                  revoked.status == 403 && errorCode(revoked) == "listen_disabled")
            prefs.agentAPIEnabled = false
            let socketStopped = await until { !fm.fileExists(atPath: paths.socket) }
            check("turning the API off removes its socket", socketStopped)
            let unavailable = await request(paths.socket, "GET", "/status")
            check("disabled API refuses new connections", unavailable.raw.hasPrefix("CONNECT-FAILED"))
            prefs.agentAPIEnabled = true
            let socketRestarted = await until { fm.fileExists(atPath: paths.socket) }
            check("the API can be enabled again without a stale socket", socketRestarted)
            let restartedDenial = await request(paths.socket, "POST", "/listen")
            check("API restart does not re-enable delegated listening",
                  restartedDenial.status == 403 && errorCode(restartedDenial) == "listen_disabled")
            prefs.agentAPIEnabled = false
            let finalSocketStopped = await until { !fm.fileExists(atPath: paths.socket) }
            check("probe leaves the API disabled", finalSocketStopped)

            // Use DEFAULT storage, with neither probeFileURL nor YAP_HISTORY_FILE:
            // those existing overrides deliberately bypass the collection gate.
            let history = HistoryStore.shared
            history.recordSpoken("privacy-probe-default-off-spoken")
            history.recordDictated("privacy-probe-default-off-dictated")
            try? await Task.sleep(nanoseconds: 150_000_000)
            check("history off keeps both in-memory lists empty", history.spoken.isEmpty && history.dictated.isEmpty)
            check("history off creates no history file", !fm.fileExists(atPath: paths.history.path))

            prefs.historyEnabled = true
            history.recordSpoken("privacy-probe-opted-in-spoken")
            history.recordDictated("privacy-probe-opted-in-dictated")
            let persisted = await until {
                self.storedTexts(paths.history, "spoken") == ["privacy-probe-opted-in-spoken"] &&
                self.storedTexts(paths.history, "dictated") == ["privacy-probe-opted-in-dictated"] &&
                AgentSelftest.mode(paths.history.path) == 0o600
            }
            check("history opt-in persists both passage types", persisted)
            check("default history file permissions are 0600", AgentSelftest.mode(paths.history.path) == 0o600)
            check("default history directory permissions are 0700",
                  AgentSelftest.mode(paths.history.deletingLastPathComponent().path) == 0o700)

            let savedBytes = try? Data(contentsOf: paths.history)
            prefs.historyEnabled = false
            history.recordSpoken("privacy-probe-off-again-spoken")
            history.recordDictated("privacy-probe-off-again-dictated")
            try? await Task.sleep(nanoseconds: 150_000_000)
            check("turning history off stops both new record types",
                  history.spoken.map(\.text) == ["privacy-probe-opted-in-spoken"] &&
                  history.dictated.map(\.text) == ["privacy-probe-opted-in-dictated"])
            check("turning history off leaves prior saved bytes unchanged",
                  savedBytes != nil && (try? Data(contentsOf: paths.history)) == savedBytes)
            let reloaded = HistoryStore()
            let restored = await until {
                reloaded.spoken.map(\.text) == ["privacy-probe-opted-in-spoken"] &&
                reloaded.dictated.map(\.text) == ["privacy-probe-opted-in-dictated"]
            }
            check("previously opted-in history reloads while collection is off", restored)
            history.clearSpoken()
            history.clearDictated()
            let cleared = await until {
                self.storedTexts(paths.history, "spoken") == [] && self.storedTexts(paths.history, "dictated") == []
            }
            check("explicit history clearing still works while collection is off", cleared)

            defaults.synchronize()
            let savedPrefs = defaults.persistentDomain(forName: paths.bundleID) ?? [:]
            check("all three privacy switches persist their off state",
                  savedPrefs["agentAPIEnabled"] as? Bool == false &&
                  savedPrefs["agentListenEnabled"] as? Bool == false &&
                  savedPrefs["historyEnabled"] as? Bool == false)
            check("no microphone capture was attempted", !captureAttempted && dictation.agentSession == nil && dictation.dictation.state == .idle)
            check("no backend or model download was started",
                  !state.backend.ownsProcess && !state.backend.ready && !state.downloader.downloading && !dictation.dictation.modelReady)
            let microphoneAfter = microphoneStatus()
            check("microphone authorization was unchanged", microphoneAfter == microphoneBefore)

            let failures = checks.filter { !$0.passed }.count
            let report = Report(checks: checks, failures: failures,
                                microphoneAuthorizationBefore: microphoneBefore,
                                microphoneAuthorizationAfter: microphoneAfter,
                                notYetTested: ["Real macOS microphone permission grant/revoke",
                                               "Live microphone recording and hardware audio output",
                                               "Interactive Settings UI clicks and cancellation of an active listen session"])
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(report).write(to: paths.root.appending(path: "privacy-report.json"), options: .atomic)
            } catch {
                print("FAIL could not write privacy report: \(error.localizedDescription)")
                return 1
            }
            print("\n\(checks.count) privacy checks, \(failures) failures")
            print("NOT YET TESTED: real microphone permission grant/revoke and live capture")
            return failures == 0 ? 0 : 1
        }
    }
}
