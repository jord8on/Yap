/// Scope of the first evaluation build. Keep the optional engine and its
/// recordings on disk while excluding Pocket and voice cloning from the app.
enum EvaluationPolicy {
    static let pocketEnabled = false
    static let pocketUnavailableMessage = "Pocket TTS and voice cloning are disabled for this evaluation."

    static func allowsEngine(_ engine: String) -> Bool {
        engine == "kokoro" || (pocketEnabled && engine == "pocket")
    }
}
