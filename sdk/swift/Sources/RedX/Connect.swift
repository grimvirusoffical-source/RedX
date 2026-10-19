import Foundation

/// The app side of the connect handshake (docs/connect.md).
public enum Connect {
    public struct Request { public let state: String, verifier: String, challenge: String
        public init(state: String, verifier: String, challenge: String) { self.state = state; self.verifier = verifier; self.challenge = challenge }
    }
    public struct Callback { public let code: String, state: String, host: String, pin: String }

    static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func random(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    /// A fresh state and PKCE S256 pair. Keep state and verifier private until the exchange.
    public static func newRequest() -> Request {
        let v = b64url(random(32))
        return Request(state: b64url(random(24)), verifier: v, challenge: b64url(Data(SHA256.hash(Data(v.utf8)))))
    }

    /// The link the owner opens: redx://connect?... or consoleURL/#/connect?...
    public static func link(provider: String, _ rq: Request, options: [String: String] = [:], consoleURL: String? = nil) -> String {
        var c = URLComponents()
        var items = [URLQueryItem(name: "v", value: "1"), URLQueryItem(name: "provider", value: provider), URLQueryItem(name: "state", value: rq.state)]
        for k in ["app", "workspace", "scope", "prefix", "label", "callback", "host", "pin", "name"] {
            if let v = options[k], !v.isEmpty { items.append(URLQueryItem(name: k, value: v)) }
        }
        items += [URLQueryItem(name: "pkce_challenge", value: rq.challenge), URLQueryItem(name: "pkce_method", value: "S256")]
        c.queryItems = items
        let qs = c.percentEncodedQuery ?? ""
        if let cu = consoleURL, let u = URL(string: cu), let s = u.scheme, let h = u.host {
            return "\(s)://\(h)\(u.port.map { ":\($0)" } ?? "")/#/connect?\(qs)"
        }
        return "redx://connect?\(qs)"
    }

    /// Read the callback URL; throws RedXError(code "state_mismatch") unless the state matches.
    public static func parseCallback(_ url: String, expectedState: String) throws -> Callback {
        guard let c = URLComponents(string: url) else { throw RedXError(status: 0, code: "bad_callback", message: "bad callback URL") }
        func g(_ k: String) -> String { c.queryItems?.first(where: { $0.name == k })?.value ?? "" }
        let cb = Callback(code: g("code"), state: g("state"), host: g("host"), pin: g("pin"))
        if cb.code.isEmpty { throw RedXError(status: 0, code: "bad_callback", message: "callback carries no code") }
        let a = Array(cb.state.utf8), b = Array(expectedState.utf8)
        var d = a.count ^ b.count
        for i in 0..<min(a.count, b.count) { d |= Int(a[i] ^ b[i]) }
        if d != 0 { throw RedXError(status: 0, code: "state_mismatch", message: "callback state does not match") }
        return cb
    }
}

extension RedXClient {
    /// Trade the approved code plus the verifier for the app's key (returned once). The client may have an empty key.
    public func exchangeConnectCode(_ code: String, _ rq: Connect.Request, deviceLabel: String? = nil) async throws -> [String: Any] {
        var b: [String: Any] = ["code": code, "pkce_verifier": rq.verifier, "state": rq.state]
        if let d = deviceLabel { b["device_label"] = d }
        return try await connectExchange(body: b).object()
    }
}
