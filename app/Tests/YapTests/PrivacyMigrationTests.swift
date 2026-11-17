import Foundation
import XCTest
@testable import Yap

final class PrivacyMigrationTests: XCTestCase {
    @MainActor
    func testFreshPreferencesRequireOptIn() throws {
        let suite = "yap.privacy.fresh.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let prefs = Prefs(defaults: defaults)

        assertPrivacySwitches(prefs, enabled: false)
        XCTAssertTrue(prefs.voiceEnabled)
    }

    @MainActor
    func testLegacyConsentResetsOnceAndExplicitChoicesSurviveRelaunch() throws {
        let suite = "yap.privacy.legacy.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        for key in ["historyEnabled", "agentAPIEnabled", "agentListenEnabled",
                    "autoUpdateCheck", "dictationEnabled", "autoStartVoice"] {
            defaults.set(true, forKey: key)
        }
        defaults.set("af_heart", forKey: "voice")
        defaults.set("multilingual", forKey: "dictationEngine")

        let upgraded = Prefs(defaults: defaults)
        assertPrivacySwitches(upgraded, enabled: false)
        XCTAssertEqual(upgraded.voice, "af_heart")
        XCTAssertEqual(upgraded.dictationEngine, "multilingual")

        upgraded.historyEnabled = true
        upgraded.agentAPIEnabled = true
        upgraded.agentListenEnabled = true
        upgraded.autoUpdateCheck = true
        upgraded.dictationEnabled = true
        upgraded.autoStartVoice = true

        let reopenedDefaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        let reopened = Prefs(defaults: reopenedDefaults)
        assertPrivacySwitches(reopened, enabled: true)
    }

    @MainActor
    private func assertPrivacySwitches(_ prefs: Prefs, enabled: Bool, line: UInt = #line) {
        XCTAssertEqual(prefs.historyEnabled, enabled, line: line)
        XCTAssertEqual(prefs.agentAPIEnabled, enabled, line: line)
        XCTAssertEqual(prefs.agentListenEnabled, enabled, line: line)
        XCTAssertEqual(prefs.autoUpdateCheck, enabled, line: line)
        XCTAssertEqual(prefs.dictationEnabled, enabled, line: line)
        XCTAssertEqual(prefs.autoStartVoice, enabled, line: line)
    }
}
