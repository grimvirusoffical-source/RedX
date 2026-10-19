import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Security)
import Security
#endif

/// A refused or failed call. status 0: not answered, or refused by the client (code "confirm_required").
public struct RedXError: Error, CustomStringConvertible {
    public let status: Int
    public let code: String?
    public let message: String
    public var description: String { status == 0 ? "redx: \(message)" : "redx: HTTP \(status): \(message)" }
}

/// A successful response.
public struct RedXResult {
    public let status: Int
    public let headers: [AnyHashable: Any]
    public let body: Data
    public func text() -> String { String(decoding: body, as: UTF8.self) }
    /// The JSON body ([:] for an empty body).
    public func json() throws -> Any { body.isEmpty ? [String: Any]() : try JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]) }
    public func object() throws -> [String: Any] { (try json() as? [String: Any]) ?? [:] }
}

/// TTL options of set (seconds).
public struct WriteOptions {
    public var ttl: Int?, sliding: Bool?, checkpoint: Int?
    public init(ttl: Int? = nil, sliding: Bool? = nil, checkpoint: Int? = nil) { self.ttl = ttl; self.sliding = sliding; self.checkpoint = checkpoint }
}

/// Client for one RedX host and key. Every operation of api/redx-api.json is a method (Operations.swift) and
/// call(_:) runs any of them by id. Dangerous operations need confirm: true. The key never appears in
/// description or in errors.
public final class RedXClient: CustomStringConvertible, @unchecked Sendable {
    public let baseURL: String
    public let db: String?
    let key: String
    let pin: String?
    let session: URLSession
    private let delegate: PinDelegate?

    static let dbName = try! NSRegularExpression(pattern: "^[a-z0-9][a-z0-9_-]{0,62}$")
    static func validDB(_ s: String) -> Bool { dbName.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }

    /// - Parameters:
    ///   - pin: SHA-256 (hex) of the host's certificate, for self-signed hosts (Apple platforms only)
    public init(url: String, key: String, db: String? = nil, pin: String? = nil, timeout: TimeInterval = 30) throws {
        guard let u = URL(string: url), let scheme = u.scheme, scheme == "http" || scheme == "https", let host = u.host else {
            throw RedXError(status: 0, code: nil, message: "url must be http(s)://host[:port]")
        }
        if let db = db, !RedXClient.validDB(db) { throw RedXError(status: 0, code: nil, message: "invalid db name") }
        var base = "\(scheme)://\(host.contains(":") ? "[\(host)]" : host)"
        if let p = u.port { base += ":\(p)" }
        baseURL = base
        self.key = key
        self.db = db
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        if let pin = pin {
            let p = pin.replacingOccurrences(of: ":", with: "").lowercased()
            guard p.count == 64 else { throw RedXError(status: 0, code: nil, message: "pin must be a SHA-256 in hex") }
            self.pin = p
            delegate = PinDelegate(pin: p)
        } else {
            self.pin = nil
            delegate = PinDelegate(pin: nil)
        }
        session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
    }

    private init(copy o: RedXClient, db: String) {
        baseURL = o.baseURL; key = o.key; pin = o.pin; self.db = db; session = o.session; delegate = o.delegate
    }

    /// A client for another database sharing this one's key and session.
    public func withDB(_ db: String) throws -> RedXClient {
        guard RedXClient.validDB(db) else { throw RedXError(status: 0, code: nil, message: "invalid db name") }
        return RedXClient(copy: self, db: db)
    }

    public var description: String { "RedXClient(\(baseURL), db=\(db ?? "(default)"))" }

    /// The danger of an operation id (.dangerous for an unknown id).
    public static func dangerOf(_ id: String) -> DangerLevel { operations[id]?.danger ?? .dangerous }

    static func scrub(_ s: String) -> String {
        s.replacingOccurrences(of: "rx_live_[A-Za-z0-9]+", with: "rx_live_[redacted]", options: .regularExpression)
    }

    func opPath(_ op: Operation, db: String?, params: [String: String]) throws -> String {
        var p = op.path
        if p.contains("{db}") {
            let d = db ?? self.db
            if let d = d, !RedXClient.validDB(d) { throw RedXError(status: 0, code: nil, message: "invalid db name") }
            if (d ?? "").isEmpty && !op.shorthand.isEmpty { p = op.shorthand } else { p = p.replacingOccurrences(of: "{db}", with: d ?? "default") }
        }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func esc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s }
        while let r = p.range(of: "\\{[a-z][a-z0-9_]*\\}", options: .regularExpression) {
            let name = String(p[r].dropFirst().dropLast())
            let v = params[name] ?? ""
            if v.isEmpty && name != "folder" { throw RedXError(status: 0, code: nil, message: "\(op.id) needs \(name)") }
            let enc = segmentParams.contains(name) ? v.split(separator: "/", omittingEmptySubsequences: false).map { esc(String($0)) }.joined(separator: "/") : esc(v)
            p.replaceSubrange(r, with: enc)
        }
        return p
    }

    static func queryString(_ q: [String: Any]?) -> String {
        guard let q = q else { return "" }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let parts: [String] = q.keys.sorted().compactMap { k in
            guard let v = q[k], !(v is NSNull) else { return nil }
            let s: String
            if let b = v as? Bool { s = b ? "1" : "0" } else { s = "\(v)" }
            return "\(k.addingPercentEncoding(withAllowedCharacters: allowed)!)=\(s.addingPercentEncoding(withAllowedCharacters: allowed)!)"
        }
        return parts.isEmpty ? "" : "?" + parts.joined(separator: "&")
    }

    /// Run any operation by id.
    @discardableResult
    public func call(_ id: String, params: [String: String] = [:], db: String? = nil, body: Any? = nil, rawBody: Data? = nil,
                     query: [String: Any]? = nil, confirm: Bool = false, headers: [String: String] = [:]) async throws -> RedXResult {
        guard let op = operations[id] else { throw RedXError(status: 0, code: nil, message: "unknown operation \(id)") }
        if op.response == "websocket" { throw RedXError(status: 0, code: nil, message: "\(id) is a stream: use stream(_:)") }
        if op.danger == .dangerous && !confirm {
            throw RedXError(status: 0, code: "confirm_required", message: "\(id) is a dangerous operation (\(op.summary)) and needs confirm: true")
        }
        var q = query ?? [:]
        if !op.hostConfirm.isEmpty {
            q["confirm"] = op.hostConfirm == "db" ? (db ?? self.db ?? "default") : (params[op.hostConfirm] ?? "")
        }
        guard let url = URL(string: baseURL + (try opPath(op, db: db, params: params)) + RedXClient.queryString(q)) else {
            throw RedXError(status: 0, code: nil, message: "bad URL")
        }
        var req = URLRequest(url: url)
        req.httpMethod = op.method
        if op.auth != "none" && !key.isEmpty { req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization") }
        switch op.request {
        case "json":
            req.httpBody = try JSONSerialization.data(withJSONObject: body ?? [String: Any](), options: [.fragmentsAllowed])
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        case "text":
            req.httpBody = rawBody ?? Data()
            req.setValue("text/x-redx-box", forHTTPHeaderField: "Content-Type")
        case "binary":
            guard let raw = rawBody else { throw RedXError(status: 0, code: nil, message: "\(id) needs rawBody") }
            req.httpBody = raw
            req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            if !headers.keys.contains(where: { $0.lowercased() == "x-redx-sha256" }) { req.setValue(SHA256.hex(raw), forHTTPHeaderField: "X-Redx-SHA256") }
        default: break
        }
        if op.response == "text" { req.setValue("text/x-redx-box", forHTTPHeaderField: "Accept") }
        if confirm { req.setValue(id, forHTTPHeaderField: "X-RedX-Confirm") }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) } catch {
            throw RedXError(status: 0, code: nil, message: RedXClient.scrub("request failed: \(error.localizedDescription)"))
        }
        guard let http = resp as? HTTPURLResponse else { throw RedXError(status: 0, code: nil, message: "no HTTP response") }
        if http.statusCode >= 300 { throw RedXClient.errorFrom(http.statusCode, data) }
        return RedXResult(status: http.statusCode, headers: http.allHeaderFields, body: data)
    }

    static func errorFrom(_ status: Int, _ data: Data) -> RedXError {
        var msg = "HTTP \(status)", code: String?
        if let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            if let e = o["error"] as? String { msg = e }
            code = o["code"] as? String
        }
        return RedXError(status: status, code: code, message: scrub(msg))
    }

    // MARK: convenience calls (same names in every RedX SDK)

    /// The value at path decoded from Box text (see BoxText.decode).
    public func get(_ path: String) async throws -> Any {
        let o = try await getPath(path: path).object()
        guard let v = o["value"] as? String else { throw RedXError(status: 0, code: nil, message: "unexpected response shape") }
        return try BoxText.decode(v)
    }

    public func getBox(_ path: String) async throws -> String { try await getPathBox(path: path).text() }

    /// Write a JSON-compatible value (dictionaries become boxes, NSNull becomes NELL).
    @discardableResult
    public func set(_ path: String, _ value: Any, _ o: WriteOptions = WriteOptions()) async throws -> RedXResult {
        var b: [String: Any] = ["value": value]
        if let t = o.ttl { b["ttl_seconds"] = t }
        if let s = o.sliding { b["sliding"] = s }
        if let c = o.checkpoint { b["checkpoint_seconds"] = c }
        return try await setPath(path: path, body: b)
    }

    @discardableResult
    public func delete(_ path: String) async throws -> RedXResult { try await deletePath(path: path) }

    /// One BoxQL command with $params.
    public func bx(_ q: String, _ params: [String: Any] = [:], db: String? = nil) async throws -> [String: Any] {
        try await call("bx", db: db, body: ["q": q, "params": params]).object()
    }

    /// Several BoxQL commands, all-or-nothing.
    public func tx(_ commands: [String], _ params: [String: Any] = [:]) async throws -> [String: Any] {
        guard !commands.isEmpty else { throw RedXError(status: 0, code: nil, message: "tx needs at least one command") }
        return try await bx("{Tx[]} = [\n  " + commands.joined(separator: ",\n  ") + "\n]", params)
    }

    @discardableResult
    public func uploadFile(pack: String, file: String, data: Data) async throws -> RedXResult { try await packPut(pack: pack, file: file, body: data) }

    /// Download a pack file; start/end are inclusive byte offsets.
    public func downloadFile(pack: String, file: String, start: Int? = nil, end: Int? = nil) async throws -> Data {
        try await call("packGet", params: ["pack": pack, "file": file], headers: RedXClient.range(start, end)).body
    }

    @discardableResult
    public func uploadMedia(lib: String, name: String, data: Data, type: String? = nil) async throws -> RedXResult {
        try await mediaPut(lib: lib, name: name, body: data, query: type.map { ["type": $0] })
    }

    public func downloadMedia(lib: String, name: String, start: Int? = nil, end: Int? = nil) async throws -> Data {
        try await call("mediaGet", params: ["lib": lib, "name": name], headers: RedXClient.range(start, end)).body
    }

    static func range(_ start: Int?, _ end: Int?) -> [String: String] {
        if start == nil && end == nil { return [:] }
        return ["Range": "bytes=\(start ?? 0)-\(end.map(String.init) ?? "")"]
    }
}

final class PinDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    let pin: String?
    init(pin: String?) { self.pin = pin }

    // never follow redirects (they could carry the key elsewhere)
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let pin = pin else { completionHandler(.performDefaultHandling, nil); return }
        #if canImport(Security)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = challenge.protectionSpace.serverTrust,
           let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
            let der = SecCertificateCopyData(leaf) as Data
            if SHA256.hex(der) == pin { completionHandler(.useCredential, URLCredential(trust: trust)); return }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
        #else
        completionHandler(.cancelAuthenticationChallenge, nil) // pinning needs the Security framework
        #endif
    }
}
