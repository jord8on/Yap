import Foundation
import XCTest
@testable import Yap

final class HistoryOptInTests: XCTestCase {
    @MainActor
    func testRecordingRequiresExplicitOptInEvenWithAnInjectedFile() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appending(path: "history.json")
        var optedIn = false
        let store = HistoryStore(fileURL: file, recordingEnabled: { optedIn })

        store.recordSpoken("Private selected text")
        store.recordDictated("Private dictation")
        XCTAssertTrue(store.spoken.isEmpty)
        XCTAssertTrue(store.dictated.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))

        optedIn = true
        store.recordSpoken("Explicitly saved text")
        store.recordDictated("Explicitly saved words")
        optedIn = false
        store.recordSpoken("Not recorded")
        store.recordDictated("Also not recorded")

        XCTAssertEqual(store.spoken.map(\.text), ["Explicitly saved text"])
        XCTAssertEqual(store.dictated.map(\.text), ["Explicitly saved words"])
        let saved = await eventually {
            (try? String(contentsOf: file, encoding: .utf8))?.contains("Explicitly saved words") == true
        }
        XCTAssertTrue(saved)
        let bytes = try String(contentsOf: file, encoding: .utf8)
        XCTAssertTrue(bytes.contains("Explicitly saved text"))
        XCTAssertFalse(bytes.contains("Private"))
        XCTAssertFalse(bytes.contains("Not recorded"))
        XCTAssertFalse(bytes.contains("Also not recorded"))
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    @MainActor
    func testMigrationPreservesLegacyPlaintextAndKeepsItReadableWithRecordingOff() async throws {
        let suite = "yap.history.legacy.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "historyEnabled")

        let file = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: file) }
        let entry = HistoryEntry(kind: .dictated, text: "Legacy dictation")
        let bytes = try JSONEncoder().encode(["dictated": [entry], "spoken": []])
        try bytes.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)

        let prefs = Prefs(defaults: defaults)
        let store = HistoryStore(fileURL: file, recordingEnabled: { prefs.historyEnabled })
        XCTAssertFalse(prefs.historyEnabled)
        let restored = await eventually { store.dictated == [entry] }
        XCTAssertTrue(restored)
        store.recordDictated("New dictation")
        XCTAssertEqual(store.dictated, [entry])
        XCTAssertEqual(try Data(contentsOf: file), bytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testLegacyHistorySymlinkIsNotReadOrChmodded() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appending(path: "unrelated.json")
        let link = dir.appending(path: "history.json")
        let bytes = Data("unrelated data".utf8)
        try bytes.write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertNil(HistoryStore.readPrivateSnapshot(at: link))
        XCTAssertEqual(try Data(contentsOf: target), bytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o644)
    }

    @MainActor
    private func eventually(_ condition: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !condition(), clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        return condition()
    }
}
