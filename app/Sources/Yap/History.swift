import Darwin
import Foundation

/// One recorded passage — text Yap spoke (TTS) or text you dictated (STT).
/// The full text is kept so a whole read can be recovered later; only the
/// number of entries is bounded (see `HistoryStore.cap`).
struct HistoryEntry: Codable, Identifiable, Equatable, Sendable {
    enum Kind: String, Codable, Sendable { case spoken, dictated }
    let id: UUID
    let date: Date
    let kind: Kind
    let text: String
    /// Context for the row: the voice for a spoken entry, the target app for a
    /// dictated one. Optional, purely informational.
    let detail: String

    init(id: UUID = UUID(), date: Date = Date(), kind: Kind, text: String, detail: String = "") {
        self.id = id
        self.date = date
        self.kind = kind
        self.text = text
        self.detail = detail
    }
}

/// Opt-in log of spoken and dictated text. Two rolling lists (newest first),
/// backed by plaintext JSON in Application Support and capped by count.
///
/// The store is the single source of truth; the History tab reads it and can
/// clear or delete entries. Recording is fire-and-forget from the read pipeline
/// (`AppState.stream`) and the dictation controller.
@MainActor
final class HistoryStore: ObservableObject {
    static let shared = HistoryStore(fileURL: defaultURL, recordingEnabled: { Prefs.shared.historyEnabled })

    /// Max entries per list. Full text is preserved; only the count is bounded so
    /// the on-disk file can't grow without limit. `nonisolated` so the pure
    /// `capped(_:)` helper can read it off the main actor.
    nonisolated static let cap = 500

    @Published private(set) var spoken: [HistoryEntry] = []
    @Published private(set) var dictated: [HistoryEntry] = []

    private let fileURL: URL
    private let recordingEnabled: @MainActor () -> Bool
    // Both encode and write hop off the main thread (arrays are COW + Sendable, so
    // the snapshot copy is cheap and safe to hand across).
    private let io = DispatchQueue(label: "com.yap.history.io", qos: .utility)
    // The initial decode runs off-main, so there's a window before the on-disk
    // history is in memory. `loaded` gates save() during that window: a save is
    // deferred (not run against a half-populated list) so we never overwrite the
    // file with less than it holds. Any entry recorded in the window is prepended
    // ahead of the restored history when the load lands, so nothing is lost.
    private var loaded = false
    private var pendingSave = false
    // Mutations during the load window must survive the merge: an entry deleted
    // (or a list cleared) before the on-disk history lands must not be resurrected
    // by it. Recorded here, then applied when the snapshot merges.
    private var deletedDuringLoad: Set<UUID> = []
    private var clearedSpokenDuringLoad = false
    private var clearedDictatedDuringLoad = false

    private struct Snapshot: Codable, Sendable { var spoken: [HistoryEntry]; var dictated: [HistoryEntry] }

    init(fileURL: URL, recordingEnabled: @escaping @MainActor () -> Bool) {
        self.fileURL = fileURL
        self.recordingEnabled = recordingEnabled
        load()
    }

    private static var defaultURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appending(path: "Yap").appending(path: "history.json")
    }

    // MARK: - Record

    func recordSpoken(_ text: String, detail: String = "") { add(kind: .spoken, text: text, detail: detail) }
    func recordDictated(_ text: String, detail: String = "") { add(kind: .dictated, text: text, detail: detail) }

    private func add(kind: HistoryEntry.Kind, text: String, detail: String) {
        guard recordingEnabled() else { return }
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return }
        let entry = HistoryEntry(kind: kind, text: t, detail: detail)
        switch kind {
        case .spoken:   spoken = Self.capped([entry] + spoken)
        case .dictated: dictated = Self.capped([entry] + dictated)
        }
        save()
    }

    // MARK: - Mutate

    func delete(_ entry: HistoryEntry) {
        if !loaded { deletedDuringLoad.insert(entry.id) }
        spoken.removeAll { $0.id == entry.id }
        dictated.removeAll { $0.id == entry.id }
        save()
    }

    func clearSpoken()   { if !loaded { clearedSpokenDuringLoad = true };   spoken = [];   save() }
    func clearDictated() { if !loaded { clearedDictatedDuringLoad = true }; dictated = []; save() }

    // MARK: - Persistence

    /// Newest-first, bounded to `cap`. Pure so `--selftest` can verify it.
    nonisolated static func capped(_ entries: [HistoryEntry], cap: Int = HistoryStore.cap) -> [HistoryEntry] {
        entries.count > cap ? Array(entries.prefix(cap)) : entries
    }

    /// Reconcile the on-disk `restored` history with `window` entries recorded
    /// during the async load, honoring window mutations: a cleared list wins
    /// (restored is dropped), and entries deleted in the window aren't resurrected.
    /// Window entries stay ahead (newest-first). Pure so `--selftest` can verify it.
    nonisolated static func merged(window: [HistoryEntry], restored: [HistoryEntry],
                                   cleared: Bool, deleted: Set<UUID>) -> [HistoryEntry] {
        guard !cleared else { return capped(window) }
        let kept = restored.filter { !deleted.contains($0.id) }
        return capped(window + kept)
    }

    /// Decode off-main so a large file never blocks the main actor at launch,
    /// then merge on the main actor. Entries recorded during the load window sit
    /// ahead of the restored history (both newest-first), so a fast first read is
    /// preserved rather than clobbered.
    private func load() {
        let url = fileURL
        Task {
            let snap = await Task.detached(priority: .userInitiated) { () -> Snapshot? in
                guard let data = Self.readPrivateSnapshot(at: url) else { return nil }
                return try? JSONDecoder().decode(Snapshot.self, from: data)
            }.value
            if let snap {
                spoken = Self.merged(window: spoken, restored: snap.spoken,
                                     cleared: clearedSpokenDuringLoad, deleted: deletedDuringLoad)
                dictated = Self.merged(window: dictated, restored: snap.dictated,
                                       cleared: clearedDictatedDuringLoad, deleted: deletedDuringLoad)
            }
            loaded = true
            deletedDuringLoad = []
            if pendingSave { pendingSave = false; save() }
        }
    }

    /// Preserve legacy bytes while restricting the existing inode before reading.
    /// Do not follow a symlink or modify a file owned by a different user.
    nonisolated static func readPrivateSnapshot(at url: URL) -> Data? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_nlink == 1,
              fchmod(fd, 0o600) == 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        return try? handle.readToEnd()
    }

    private func save() {
        // Don't persist until the initial load has merged in the on-disk history,
        // or an early save would truncate the file to just the in-window entries.
        guard loaded else { pendingSave = true; return }
        let spokenCopy = spoken, dictatedCopy = dictated, url = fileURL
        io.async {
            guard let data = try? JSONEncoder().encode(
                Snapshot(spoken: spokenCopy, dictated: dictatedCopy)) else { return }
            do {
                try Self.writePrivateSnapshot(data, to: url)
            } catch {
                try? FileHandle.standardError.write(contentsOf: Data("Yap: could not save history\n".utf8))
            }
        }
    }

    private nonisolated static func writePrivateSnapshot(_ data: Data, to url: URL) throws {
        let fm = FileManager.default
        let parent = url.deletingLastPathComponent()
        if !fm.fileExists(atPath: parent.path) {
            try fm.createDirectory(at: parent, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        }
        // Stage privately beside the destination, then replace it atomically.
        // The replacement is already 0600 when it becomes visible.
        let staging = parent.appending(path: ".history-\(UUID().uuidString)")
        try fm.createDirectory(at: staging, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: staging) }
        let snapshot = staging.appending(path: "snapshot.json")
        try data.write(to: snapshot)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: snapshot.path)
        guard rename(snapshot.path, url.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
