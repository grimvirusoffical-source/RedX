import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A real redxd on a free port with a throwaway data dir (REDXD_BIN, or built from the repository). The
/// bootstrap admin key is read from its output and never printed.
final class Host {
    let url: String
    private(set) var adminKey = ""
    let tmp: URL
    let bin: String
    let port: Int
    var proc: Process?
    private let lock = NSLock()
    private var out = ""

    static var repoRoot: URL {
        var u = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while !FileManager.default.fileExists(atPath: u.appendingPathComponent("api/redx-api.json").path) { u = u.deletingLastPathComponent() }
        return u
    }

    init() throws {
        tmp = FileManager.default.temporaryDirectory.appendingPathComponent("redx-sdk-swift-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        if let b = ProcessInfo.processInfo.environment["REDXD_BIN"], !b.isEmpty { bin = b } else {
            bin = tmp.appendingPathComponent("redxd").path
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            p.arguments = ["go", "build", "-o", bin, "./cmd/redxd"]
            p.currentDirectoryURL = Host.repoRoot
            try p.run(); p.waitUntilExit()
            guard p.terminationStatus == 0 else { throw NSError(domain: "build redxd", code: 1) }
        }
        port = Int.random(in: 20000...45000)
        url = "http://127.0.0.1:\(port)"
        try spawn()
    }

    func spawn() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["run", "--no-open", "--bootstrap", "console", "--data-dir", tmp.appendingPathComponent("data").path, "--listen", "127.0.0.1:\(port)"]
        p.environment = ["PATH": ProcessInfo.processInfo.environment["PATH"] ?? "", "HOME": tmp.path]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard let self = self, !d.isEmpty else { return }
            self.lock.lock(); defer { self.lock.unlock() }
            if self.adminKey.isEmpty {
                self.out += String(decoding: d, as: UTF8.self)
                if let r = self.out.range(of: "rx_live_[A-Za-z0-9]{43}", options: .regularExpression) { self.adminKey = String(self.out[r]); self.out = "" }
            }
        }
        try p.run()
        proc = p
        for _ in 0..<400 {
            if !p.isRunning { throw NSError(domain: "redxd exited early", code: 2) }
            if let u = URL(string: url + "/healthz"), let d = try? Data(contentsOf: u), !d.isEmpty {
                lock.lock(); let k = adminKey; lock.unlock()
                if !k.isEmpty { return }
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw NSError(domain: "redxd did not become ready", code: 3)
    }

    func kill() {
        if let p = proc, p.isRunning { p.terminate(); kill9(p); p.waitUntilExit() }
    }

    private func kill9(_ p: Process) {
        #if os(Linux) || os(macOS)
        _ = Foundation.kill(p.processIdentifier, SIGKILL)
        #endif
    }

    /// Kill and start again on the same port and data (to test reconnects).
    func restart(down: TimeInterval = 0.3) throws { kill(); Thread.sleep(forTimeInterval: down); try spawn() }

    func stop() { kill(); try? FileManager.default.removeItem(at: tmp) }
}
