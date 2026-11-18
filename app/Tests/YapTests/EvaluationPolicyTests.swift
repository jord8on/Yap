import Foundation
import XCTest
@testable import Yap

final class EvaluationPolicyTests: XCTestCase {
    @MainActor
    func testLegacyPocketPreferencesCannotSelectOrPreloadIt() throws {
        let suite = "yap.evaluation.pocket.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("pocket", forKey: "engine")
        defaults.set("legacy-clone", forKey: "hdVoice")
        defaults.set(true, forKey: "autoLoadHD")

        let prefs = Prefs(defaults: defaults)
        XCTAssertFalse(EvaluationPolicy.pocketEnabled)
        XCTAssertFalse(prefs.autoLoadHD)
        XCTAssertEqual(prefs.engine, "kokoro")
        prefs.selectEngine("pocket")
        XCTAssertEqual(prefs.engine, "kokoro")
        XCTAssertEqual(prefs.hdVoice, "legacy-clone")
        XCTAssertEqual(defaults.string(forKey: "engine"), "pocket")
    }

    func testAgentCannotSelectPocketEvenWhenInstalled() throws {
        let voice = EngineVoice(engine: "pocket", voiceId: "eve", label: "Eve", section: "Pocket")
        let request = AppState.resolveRead(.init(voice: "pocket:eve"), combined: [voice], hdInstalled: true,
                                           prefsEngine: "kokoro", prefsVoice: "am_puck",
                                           prefsHDVoice: "eve", prefsSpeed: 1)
        switch request {
        case .success(let params):
            XCTFail("Unexpected engine: \(params.engine)")
        case .failure(let error):
            XCTAssertEqual(error.code, "engine_unavailable")
        }

        let defaultRead = try AppState.resolveRead(.init(), combined: [], hdInstalled: true,
                                                   prefsEngine: "pocket", prefsVoice: "am_puck",
                                                   prefsHDVoice: "eve", prefsSpeed: 1).get()
        XCTAssertEqual(defaultRead.engine, "kokoro")
        XCTAssertEqual(defaultRead.voice, "am_puck")
    }
}
