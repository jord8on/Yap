import Foundation
import CryptoKit
import Darwin
import Security

/// The sidecar and client share a private bearer token and a pinned TLS identity.
struct BackendAuth: Sendable {
    static let local = BackendAuth(
        tokenFileURL: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appending(path: "Yap/auth-token"),
        migrateDefaultDirectory: true
    )

    static func proof(nonce: String) -> String? { local.proof(for: nonce) }

    let tokenFileURL: URL
    private let migrateDefaultDirectory: Bool

    var bearerToken: String? {
        Self.loadOrCreate(at: tokenFileURL, migrateDefaultDirectory: migrateDefaultDirectory)
    }

    init(tokenFileURL: URL, migrateDefaultDirectory: Bool = false) {
        self.tokenFileURL = tokenFileURL
        self.migrateDefaultDirectory = migrateDefaultDirectory
    }

    private static func openDirectory(for url: URL, migrateDefaultDirectory: Bool = false) -> Int32? {
        let parent = url.deletingLastPathComponent()
        let fd = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        var info = stat()
        if fstat(fd, &info) == 0, info.st_uid == geteuid() {
            if info.st_mode & 0o7777 == 0o700 { return fd }
            // Earlier Yap versions created this directory with the usual 0755 umask.
            // Tighten the known directory by descriptor and refuse previously writable directories.
            if migrateDefaultDirectory, info.st_mode & 0o7777 == 0o755, fchmod(fd, 0o700) == 0 {
                return fd
            }
        }
        close(fd)
        return nil
    }

    private static func readPrivateFile(_ fd: Int32, maxBytes: Int) -> Data? {
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_mode & 0o7777 == 0o600,
              info.st_size > 0, info.st_size <= off_t(maxBytes),
              let data = try? handle.read(upToCount: maxBytes + 1),
              data.count == Int(info.st_size) else { return nil }
        return data
    }

    private static func readToken(_ fd: Int32) -> String? {
        guard let bytes = readPrivateFile(fd, maxBytes: 128),
              let token = String(data: bytes, encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t\r\n")),
              token.utf8.count == 43,
              token.utf8.allSatisfy({
                  (65...90).contains($0) || (97...122).contains($0) ||
                  (48...57).contains($0) || $0 == 45 || $0 == 95
              }) else { return nil }
        return token
    }

    private static func loadOrCreate(at url: URL, migrateDefaultDirectory: Bool) -> String? {
        let parent = url.deletingLastPathComponent()
        if mkdir(parent.path, 0o700) != 0, errno != EEXIST {
            guard errno == ENOENT,
                  (try? FileManager.default.createDirectory(at: parent.deletingLastPathComponent(),
                                                            withIntermediateDirectories: true)) != nil,
                  mkdir(parent.path, 0o700) == 0 || errno == EEXIST else { return nil }
        }
        guard let directory = openDirectory(for: url, migrateDefaultDirectory: migrateDefaultDirectory) else {
            return nil
        }
        defer { close(directory) }

        let name = url.lastPathComponent
        let readFlags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        let existing = open(url.path, readFlags)
        if existing >= 0 { return readToken(existing) }
        guard errno == ENOENT else { return nil }

        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            return nil
        }
        let token = Data(random).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        // Write completely before publishing. linkat refuses to replace an
        // existing entry, including a file published by a concurrent launch.
        let temp = ".auth-token-\(UUID().uuidString)"
        let fd = open(parent.appending(path: temp).path,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { return nil }
        defer { unlinkat(directory, temp, 0) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            guard fchmod(fd, 0o600) == 0 else { return nil }
            try handle.write(contentsOf: Data(token.utf8))
            try handle.close()
        } catch {
            return nil
        }

        if linkat(directory, temp, directory, name, 0) == 0 { return token }
        guard errno == EEXIST else { return nil }
        let winner = open(url.path, readFlags)
        return winner >= 0 ? readToken(winner) : nil
    }

    /// The sidecar publishes the certificate on first launch, so read it when
    /// URLSession receives the TLS challenge.
    var pinnedTLSCertificateDER: Data? {
        guard let directory = Self.openDirectory(for: tokenFileURL) else { return nil }
        defer { close(directory) }
        let cert = tokenFileURL.deletingLastPathComponent().appending(path: "backend-tls-cert.pem")
        let fd = open(cert.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0, let data = Self.readPrivateFile(fd, maxBytes: 16 * 1024),
              let pem = String(data: data, encoding: .ascii),
              let begin = pem.range(of: "-----BEGIN CERTIFICATE-----"),
              let end = pem[begin.upperBound...].range(of: "-----END CERTIFICATE-----") else {
            return nil
        }
        let base64 = pem[begin.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
        return Data(base64Encoded: String(base64))
    }

    /// HMAC-SHA256(token, nonce) as lowercase hex, matching /verify.
    func proof(for nonce: String) -> String? {
        guard let bearerToken else { return nil }
        return Self.proof(token: bearerToken, nonce: nonce)
    }

    static func proof(token: String, nonce: String) -> String {
        let key = SymmetricKey(data: Data(token.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(nonce.utf8), using: key)
        return mac.map { String(format: "%02x", $0) }.joined()
    }
}
