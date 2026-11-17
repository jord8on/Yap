import XCTest
@testable import Yap

final class ModelNetworkPolicyTests: XCTestCase {
    func testSanitizedChildEnvironmentDropsAmbientOverrides() {
        let removed = [
            "HF_TOKEN", "HF_TOKEN_PATH", "HF_HOME", "HUGGING_FACE_HUB_TOKEN",
            "HUGGINGFACE_HUB_TOKEN", "HUGGINGFACEHUB_API_TOKEN",
            "Hf_Endpoint", "HF_INFERENCE_ENDPOINT", "HUGGINGFACE_HUB_BASE_URL",
            "HF_HUB_BASE_URL", "REGISTRY_URL", "model_registry_url",
            "HTTP_PROXY", "https_proxy", "All_Proxy", "no_PROXY", "Proxy",
            "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP",
            "VIRTUAL_ENV", "__PYVENV_LAUNCHER__",
            "DYLD_INSERT_LIBRARIES", "dyld_fallback_library_path", "__XPC_DYLD_LIBRARY_PATH",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LIBRARY_PATH",
            "PIP_INDEX_URL", "UV_EXTRA_INDEX_URL", "hf_hub_disable_implicit_token",
            "OPENAI_API_KEY", "AWS_SESSION_TOKEN", "GH_TOKEN", "UNLISTED_VENDOR_SECRET",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "OPENSSL_CONF", "OPENSSL_MODULES", "SSLKEYLOGFILE", "NETRC", "BASH_ENV",
        ]
        var input = Dictionary(uniqueKeysWithValues: removed.map { ($0, "fixture") })
        input["LANG"] = "en_US.UTF-8"
        input["PATH"] = "/untrusted/bin"
        input["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "0"
        input["HF_HUB_DISABLE_TELEMETRY"] = "0"
        input["HF_HUB_DISABLE_UPDATE_CHECK"] = "0"
        input["DO_NOT_TRACK"] = "0"

        let sanitized = ModelNetworkPolicy.sanitizedEnvironment(input)
        XCTAssertEqual(sanitized, [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "HF_HUB_DISABLE_UPDATE_CHECK": "1",
            "DO_NOT_TRACK": "1",
        ])
        XCTAssertEqual(ModelNetworkPolicy.sanitizedEnvironment(sanitized), sanitized)
    }
}
