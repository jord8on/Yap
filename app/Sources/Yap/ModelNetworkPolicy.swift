import Darwin
import FluidAudio
import Foundation

/// Use the public model registry and omit ambient credentials and overrides.
enum ModelNetworkPolicy {
    private static let publicRegistry = "https://huggingface.co"
    private static let publicModelFlags = [
        "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_DISABLE_UPDATE_CHECK": "1",
        "DO_NOT_TRACK": "1",
    ]
    private static let blockedKeys: Set<String> = [
        "DO_NOT_TRACK", "REGISTRY_URL", "MODEL_REGISTRY_URL", "PROXY",
        "VIRTUAL_ENV", "__PYVENV_LAUNCHER__", "LIBRARY_PATH", "LIBPATH",
        "SHLIB_PATH", "LTDL_LIBRARY_PATH",
        "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
        "UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        "OPENSSL_CONF", "OPENSSL_MODULES", "SSLKEYLOGFILE", "NETRC", "UV_CONFIG_FILE",
    ]
    private static let blockedPrefixes = [
        "HF_", "HUGGINGFACE", "HUGGING_FACE_", "PYTHON", "_PYTHON", "__PYTHON",
        "DYLD_", "__XPC_DYLD_", "LD_",
    ]

    // The sidecar does not need credentials belonging to other applications.
    // A denylist cannot enumerate every vendor's token or trust override.
    private static let childKeys: Set<String> = [
        "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
        "LC_MESSAGES", "LC_COLLATE", "LC_NUMERIC", "LC_MONETARY", "LC_TIME",
        "TZ", "__CF_USER_TEXT_ENCODING",
    ]

    /// Start with a small allowlist, then add only reviewed app-owned settings.
    static func sanitizedEnvironment(_ input: [String: String]) -> [String: String] {
        var output = input.filter { childKeys.contains($0.key) }
        output["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        for (key, value) in publicModelFlags { output[key] = value }
        return output
    }

    static func apply() {
        for key in ProcessInfo.processInfo.environment.keys where isBlocked(key) {
            _ = unsetenv(key)
        }
        for (key, value) in publicModelFlags { _ = setenv(key, value, 1) }

        // Set the FluidAudio API before constructing either dictation engine.
        ModelRegistry.baseURL = publicRegistry
    }

    private static func isBlocked(_ name: String) -> Bool {
        let key = name.uppercased()
        return blockedKeys.contains(key)
            || key.hasSuffix("_PROXY")
            || blockedPrefixes.contains(where: { key.hasPrefix($0) })
    }
}
