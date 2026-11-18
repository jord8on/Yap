import Foundation
import XCTest
@testable import Yap

final class BackendAuthenticationTests: XCTestCase {
    private let speechCanary = "private-speech-canary"

    func testCleartextOriginIsRejectedBeforeConnecting() async throws {
        try await withPeer(mode: "wrong-proof") { peer in
            let client = BackendClient(base: peer.url(scheme: "http"), auth: peer.auth)
            await self.assertSpeechRejected(client)
            XCTAssertTrue(try peer.events().isEmpty)
        }
    }

    func testUnsafeTokenIsRejectedBeforeConnecting() async throws {
        try await withPeer(mode: "wrong-proof") { peer in
            let fm = FileManager.default
            try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: peer.auth.tokenFileURL.path)
            XCTAssertNil(peer.auth.bearerToken)
            let client = BackendClient(base: peer.url(), auth: peer.auth)
            await self.assertSpeechRejected(client)
            XCTAssertTrue(try peer.events().isEmpty)
        }
    }

    func testPinnedListenerWithWrongTokenProofReceivesOnlyTheChallenge() async throws {
        try await withPeer(mode: "wrong-proof") { peer in
            let client = BackendClient(base: peer.url(), auth: peer.auth)
            await self.assertSpeechRejected(client)
            try self.assertOnlyVerificationReachedPeer(peer, expectedConnections: 1)
        }
    }

    func testListenerIdentityChangeAfterVerificationCannotReceiveSpeech() async throws {
        try await withPeer(mode: "change-identity") { peer in
            let client = BackendClient(base: peer.url(), auth: peer.auth)
            await self.assertSpeechRejected(client)
            // The second handshake must reach the listener after a successful
            // HMAC challenge. A test with a broken challenge would stop early.
            try self.assertOnlyVerificationReachedPeer(peer, expectedConnections: 2)
        }
    }

    private func assertSpeechRejected(_ client: BackendClient, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await client.wav(text: speechCanary, voice: "af_heart", speed: 1)
            XCTFail("Speech request unexpectedly succeeded", file: file, line: line)
        } catch {
            // Each caller also checks the listener's connection and HTTP records.
        }
    }

    private func assertOnlyVerificationReachedPeer(_ peer: Peer, expectedConnections: Int,
                                                   file: StaticString = #filePath, line: UInt = #line) throws {
        let events = try peer.events()
        let count = events.filter { $0.kind == "tcp" }.count
        XCTAssertGreaterThanOrEqual(count, expectedConnections, file: file, line: line)
        let requests = events.filter { $0.kind == "http" }
        XCTAssertEqual(requests.map(\.path), ["/verify"], file: file, line: line)
        XCTAssertTrue(requests.allSatisfy { $0.hasAuthorization == false && $0.hasBody == false },
                      file: file, line: line)
    }

    private struct Peer {
        struct Event: Decodable {
            let kind: String
            let path: String?
            let hasAuthorization: Bool?
            let hasBody: Bool?
        }

        let port: Int
        let auth: BackendAuth
        let eventFile: URL

        func url(scheme: String = "https") -> URL {
            URL(string: "\(scheme)://127.0.0.1:\(port)")!
        }

        func events() throws -> [Event] {
            let lines = try String(contentsOf: eventFile, encoding: .utf8).split(whereSeparator: \.isNewline)
            return try lines.map { try JSONDecoder().decode(Event.self, from: Data($0.utf8)) }
        }
    }

    private func withPeer(mode: String, _ body: (Peer) async throws -> Void) async throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appending(path: "yap-auth-tests-\(UUID().uuidString)")
        try fm.createDirectory(at: root, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: root) }

        let auth = BackendAuth(tokenFileURL: root.appending(path: "auth-token"))
        _ = try XCTUnwrap(auth.bearerToken)
        let backendSource = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "backend")
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = ["-B", "-E", "-s", "-c", Self.peerScript, root.path, backendSource.path, mode]
        child.environment = ["PATH": "/usr/bin:/bin"]
        try child.run()
        defer {
            if child.isRunning { child.terminate() }
            child.waitUntilExit()
        }

        let portFile = root.appending(path: "port")
        for _ in 0..<100 {
            if let raw = try? String(contentsOf: portFile, encoding: .utf8), let port = Int(raw) {
                try await body(Peer(port: port, auth: auth, eventFile: root.appending(path: "events")))
                return
            }
            if !child.isRunning { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("TLS test peer did not publish a port")
    }

    private static let peerScript = #"""
    import hashlib
    import hmac
    import http.server
    import json
    import ssl
    import sys
    import urllib.parse
    from pathlib import Path

    root, backend, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    sys.path.insert(0, backend)
    from local_tls import ensure_identity

    token_file = root / "auth-token"
    token = token_file.read_text(encoding="ascii").strip()

    def identity(path):
        cert, key = ensure_identity(path)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        return context

    trusted = identity(token_file)
    if mode == "change-identity":
        other = root / "other"
        other.mkdir(mode=0o700)
        replacement = identity(other / "auth-token")

    events = root / "events"
    events.touch()

    def record(kind, **fields):
        with events.open("a", encoding="utf-8") as log:
            log.write(json.dumps({"kind": kind, **fields}) + "\n")

    class Server(http.server.HTTPServer):
        context = trusted

        def get_request(self):
            connection, address = super().get_request()
            record("tcp")
            connection.settimeout(3)
            try:
                return self.context.wrap_socket(connection, server_side=True), address
            except OSError:
                connection.close()
                raise

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            self.record_request(url.path)
            if url.path != "/verify":
                self.send_error(404)
                return

            nonce = urllib.parse.parse_qs(url.query)["nonce"][0]
            secret = "wrong-token" if mode == "wrong-proof" else token
            proof = hmac.new(secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()
            body = json.dumps({"proof": proof}).encode()
            if mode == "change-identity":
                # Force the next request onto a fresh TLS connection with a new key.
                self.server.context = replacement
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.record_request(self.path)
            self.send_error(403)

        def record_request(self, path):
            record("http", path=path, hasAuthorization="Authorization" in self.headers,
                   hasBody=int(self.headers.get("Content-Length", "0")) > 0)

        def log_message(self, *_):
            pass

    server = Server(("127.0.0.1", 0), Handler)
    port_temp = root / ".port"
    port_temp.write_text(str(server.server_port))
    port_temp.rename(root / "port")
    server.serve_forever()
    """#
}
