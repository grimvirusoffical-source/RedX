import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One change from subscribe or watch. value is Box text; data its decoded form.
public struct RedXEvent {
    public let path: String, op: String, value: String, at: String
    public let data: Any?
    public let raw: [String: Any]
}

/// Stream options. With reconnect an unexpected close is followed by reconnects with exponential backoff
/// (jittered). Events while disconnected are not replayed: re-read state in onReconnect. A refusal ends it.
public struct StreamOptions {
    public var reconnect: Bool
    public var minBackoff: TimeInterval
    public var maxBackoff: TimeInterval
    public var onReconnect: (@Sendable () -> Void)?
    public init(reconnect: Bool = false, minBackoff: TimeInterval = 0.25, maxBackoff: TimeInterval = 10, onReconnect: (@Sendable () -> Void)? = nil) {
        self.reconnect = reconnect; self.minBackoff = minBackoff; self.maxBackoff = maxBackoff; self.onReconnect = onReconnect
    }
}

/// An open stream: iterate events (for try await ev in stream.events) and call close() when done.
public final class RedXStream: @unchecked Sendable {
    public let events: AsyncThrowingStream<RedXEvent, Error>
    private let cont: AsyncThrowingStream<RedXEvent, Error>.Continuation
    private var task: Task<Void, Never>?
    private let lock = NSLock()
    private var current: URLSessionWebSocketTask?

    init() {
        var c: AsyncThrowingStream<RedXEvent, Error>.Continuation!
        events = AsyncThrowingStream(bufferingPolicy: .bufferingNewest(1024)) { c = $0 }
        cont = c
    }

    func set(_ t: URLSessionWebSocketTask) { lock.lock(); current = t; lock.unlock() }

    func start(first: URLSessionWebSocketTask, dial: @escaping @Sendable () async throws -> URLSessionWebSocketTask, o: StreamOptions) {
        set(first)
        task = Task { [weak self] in
            guard let self = self else { return }
            var ws = first
            while !Task.isCancelled {
                await self.pump(ws)
                if Task.isCancelled { break }
                guard o.reconnect else { self.cont.finish(throwing: RedXError(status: 0, code: nil, message: "stream closed by the host")); return }
                var delay = o.minBackoff
                var next: URLSessionWebSocketTask?
                while !Task.isCancelled && next == nil {
                    try? await Task.sleep(nanoseconds: UInt64((delay / 2 + Double.random(in: 0...(delay / 2))) * 1e9))
                    delay = min(delay * 2, o.maxBackoff)
                    do { next = try await dial() } catch let e as RedXError where [400, 401, 403, 404].contains(e.status) {
                        self.cont.finish(throwing: e); return
                    } catch { continue }
                }
                guard let n = next else { break }
                ws = n
                self.set(n)
                o.onReconnect?()
            }
            self.cont.finish()
        }
    }

    private func pump(_ ws: URLSessionWebSocketTask) async {
        while true {
            let msg: URLSessionWebSocketTask.Message
            do { msg = try await ws.receive() } catch { return }
            var data: Data
            switch msg {
            case .string(let s): data = Data(s.utf8)
            case .data(let d): data = d
            @unknown default: continue
            }
            guard let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
            let op = o["op"] as? String ?? "", value = o["value"] as? String ?? ""
            let decoded: Any? = (op == "set" && !value.isEmpty) ? (try? BoxText.decode(value)) : nil
            cont.yield(RedXEvent(path: o["path"] as? String ?? "", op: op, value: value, at: o["at"] as? String ?? "", data: decoded, raw: o))
        }
    }

    /// The next event, or nil when the stream ended or nothing arrived within timeout seconds.
    public func next(timeout: TimeInterval = 10) async throws -> RedXEvent? {
        try await withThrowingTaskGroup(of: RedXEvent?.self) { g in
            g.addTask { var it = self.events.makeAsyncIterator(); return try await it.next() }
            g.addTask { try await Task.sleep(nanoseconds: UInt64(timeout * 1e9)); return nil }
            let r = try await g.next() ?? nil
            g.cancelAll()
            return r
        }
    }

    public func close() {
        task?.cancel()
        lock.lock(); let c = current; lock.unlock()
        c?.cancel(with: .normalClosure, reason: Data("bye".utf8))
        cont.finish()
    }
}

extension RedXClient {
    /// Changes matching a path pattern such as "players.red-xai.db:Player[ID=*]".
    public func subscribe(_ pattern: String, _ o: StreamOptions = StreamOptions(), db: String? = nil) async throws -> RedXStream {
        try await stream("subscribe", query: ["path": pattern], o, db: db)
    }

    /// The changes a BoxQL {Watch[]} command matches.
    public func watch(_ q: String, _ params: [String: Any]? = nil, _ o: StreamOptions = StreamOptions(), db: String? = nil) async throws -> RedXStream {
        var query: [String: Any] = ["q": q]
        if let p = params { query["params"] = String(decoding: try JSONSerialization.data(withJSONObject: p), as: UTF8.self) }
        return try await stream("bxWatch", query: query, o, db: db)
    }

    /// Open any WebSocket operation (subscribe, bxWatch, rulesSubscribe) by id.
    public func stream(_ id: String, query: [String: Any]? = nil, _ o: StreamOptions = StreamOptions(), db: String? = nil) async throws -> RedXStream {
        guard let op = operations[id], op.response == "websocket" else { throw RedXError(status: 0, code: nil, message: "\(id) is not a stream operation") }
        let path = try opPath(op, db: db, params: [:])
        let url = "ws" + baseURL.dropFirst(4) + path + RedXClient.queryString(query)
        let probe = baseURL + path + RedXClient.queryString(query)
        let dial: @Sendable () async throws -> URLSessionWebSocketTask = { [self] in try await self.dialWS(url, probe: probe) }
        let first = try await dial()
        let s = RedXStream()
        s.start(first: first, dial: dial, o: o)
        return s
    }

    func dialWS(_ url: String, probe: String) async throws -> URLSessionWebSocketTask {
        guard let u = URL(string: url) else { throw RedXError(status: 0, code: nil, message: "bad URL") }
        var req = URLRequest(url: u)
        if !key.isEmpty { req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization") }
        let t = session.webSocketTask(with: req)
        t.resume()
        do {
            #if canImport(FoundationNetworking)
            // swift-corelibs-foundation (Linux, Windows) does not complete this handshake against redxd: streams
            // are supported on Apple platforms only. Use the C# or Go SDK, or the C ABI, elsewhere.
            throw RedXError(status: 0, code: "unsupported", message: "WebSocket streams need Apple's URLSession (macOS, iOS, tvOS)")
            #else
            // a ping completes only once the upgrade succeeded
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                t.sendPing { e in if let e = e { c.resume(throwing: e) } else { c.resume() } }
            }
            #endif
            return t
        } catch let e as RedXError where e.code == "unsupported" {
            t.cancel()
            throw e
        } catch {
            t.cancel()
            // the handshake status is not exposed by URLSession: ask the host with a plain GET
            var r = URLRequest(url: URL(string: probe)!)
            if !key.isEmpty { r.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization") }
            // A probe answered by the WebSocket upgrader itself (Sec-WebSocket-Version set) passed every host
            // check: the stream would be accepted, so the dial failure was transient (host restarting). Retry it.
            if let (d, resp) = try? await session.data(for: r), let h = resp as? HTTPURLResponse, h.statusCode >= 400,
               h.value(forHTTPHeaderField: "Sec-WebSocket-Version") == nil {
                throw RedXClient.errorFrom(h.statusCode, d)
            }
            throw RedXError(status: 0, code: nil, message: RedXClient.scrub("stream: \(error.localizedDescription)"))
        }
    }
}
