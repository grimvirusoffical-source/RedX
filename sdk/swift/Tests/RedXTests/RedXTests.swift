import XCTest
@testable import RedX

final class OfflineTests: XCTestCase {
    func testTableMatchesSpec() throws {
        let d = try Data(contentsOf: Host.repoRoot.appendingPathComponent("api/redx-api.json"))
        let spec = try JSONSerialization.jsonObject(with: d) as! [String: Any]
        let ops = spec["operations"] as! [[String: Any]]
        XCTAssertEqual(ops.count, operations.count)
        for o in ops {
            let id = o["id"] as! String
            XCTAssertEqual("\(operations[id]!.danger)", o["danger"] as? String, id)
        }
        for id in ["deleteDatabase", "createKey", "revokeKey", "promote", "repoint", "connectApprove", "createJoinToken"] {
            XCTAssertEqual(RedXClient.dangerOf(id), .dangerous, id)
        }
        XCTAssertEqual(RedXClient.dangerOf("nope"), .dangerous)
        XCTAssertEqual(RedXClient.dangerOf("getPath"), .safe)
    }

    func testSHA256AndBoxText() throws {
        XCTAssertEqual(SHA256.hex(Data("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(SHA256.hex(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(try BoxText.decode("\"a\\\"b\\u00e9\"") as? String, "a\"bé")
        XCTAssertEqual(try BoxText.decode("-1.5e2") as? Double, -150)
        XCTAssertTrue(try BoxText.decode("NELL") is NSNull)
        let arr = try BoxText.decode(";[\"a\", 2, TRUE]:") as! [Any]
        XCTAssertEqual(arr[0] as? String, "a"); XCTAssertEqual(arr[1] as? Double, 2); XCTAssertEqual(arr[2] as? Bool, true)
        let box = try BoxText.decode("[ {A[]} = 1, {B[ID=7]} = [ {C[]} = ;[]: ] ]") as! [String: Any]
        XCTAssertEqual(box["A"] as? Double, 1)
        XCTAssertEqual(((box["B[ID=7]"] as! [String: Any])["C"] as! [Any]).count, 0)
        XCTAssertThrowsError(try BoxText.decode("[ {A[]} = "))
    }

    func testDangerousRefusedWithoutRequest() async throws {
        let c = try RedXClient(url: "http://127.0.0.1:9", key: "rx_" + "live_" + String(repeating: "x", count: 43))
        for id in ["deleteDatabase", "promote", "connectApprove", "createPairingCode"] {
            do { try await c.call(id, db: "x"); XCTFail(id) } catch let e as RedXError {
                XCTAssertEqual(e.code, "confirm_required"); XCTAssertEqual(e.status, 0)
            }
        }
        XCTAssertFalse(c.description.contains("xxxx"))
    }
}

final class LiveTests: XCTestCase {
    var host: Host!
    override func setUpWithError() throws { host = try Host() }
    override func tearDown() { host?.stop() }

    func status(_ f: () async throws -> Void) async -> Int {
        do { try await f(); return 0 } catch let e as RedXError { return e.status } catch { return -1 }
    }

    func testEverythingAgainstARealHost() async throws {
        let admin = try RedXClient(url: host.url, key: host.adminKey)
        let v1 = try await admin.health().object()["status"] as? String
        XCTAssertEqual(v1, "ok")
        try await admin.createDatabase(body: ["name": "sdksw"])
        let v2 = try await admin.listDatabases().text().contains("sdksw")
        XCTAssertTrue(v2)
        let c = try admin.withDB("sdksw")

        try await c.set("p.red-xai.db:P[ID=1]", ["Name": "Ann", "Level": 5])
        let p = try await c.get("p.red-xai.db:P[ID=1]") as! [String: Any]
        XCTAssertEqual(p["Name"] as? String, "Ann"); XCTAssertEqual(p["Level"] as? Double, 5)
        let v3 = try await c.getBox("p.red-xai.db:P[ID=1].Name")
        XCTAssertEqual(v3, "\"Ann\"")
        try await c.set("s.red-xai-db-qs:S[ID=1]", "short", WriteOptions(ttl: 1))
        try await Task.sleep(nanoseconds: 2_500_000_000)
        let st404 = await status { _ = try await c.get("s.red-xai-db-qs:S[ID=1]") }
        XCTAssertEqual(st404, 404)
        let v4 = try await c.bx("{Get[]} = p:P[Level >= $min] -> Name", ["min": 3])["count"] as? Int
        XCTAssertEqual(v4, 1)
        let tx = try await c.tx(["{Set[]} = p:P[ID=1].Level = $l", "{Add[]} = p:P[ID=3] = [ {Name[]} = \"Cy\" ]"], ["l": 9])
        XCTAssertEqual((tx["results"] as? [Any])?.count, 2)
        let st409 = await status { _ = try await c.tx(["{Require[]} = p:P[ID=1, Level > 100]", "{Delete[]} = p:P[ID=3]"]) }
        XCTAssertEqual(st409, 409)
        do { try await admin.deleteDatabase(db: "sdksw"); XCTFail("unconfirmed delete") } catch let e as RedXError { XCTAssertEqual(e.code, "confirm_required") }

        let k = try await admin.createKey(body: ["db": "sdksw", "scope": "read", "label": "sw-ro"], confirm: true).object()
        let ro = try RedXClient(url: host.url, key: k["key"] as! String, db: "sdksw")
        let v5 = try await ro.get("p.red-xai.db:P[ID=1].Name") as? String
        XCTAssertEqual(v5, "Ann")
        let st403 = await status { try await ro.set("p.red-xai.db:P[ID=9]", 1) }
        XCTAssertEqual(st403, 403)
        try await admin.revokeKey(id: k["id"] as! String, confirm: true)
        let st401 = await status { _ = try await ro.get("p.red-xai.db:P[ID=1]") }
        XCTAssertEqual(st401, 401)

        var data = Data(count: 300000)
        for i in 0..<data.count { data[i] = UInt8.random(in: 0...255) }
        try await c.uploadFile(pack: "assets", file: "lvl/one.bin", data: data)
        let v6 = try await c.downloadFile(pack: "assets", file: "lvl/one.bin")
        XCTAssertEqual(v6, data)
        let v7 = try await c.downloadFile(pack: "assets", file: "lvl/one.bin", start: 10, end: 19)
        XCTAssertEqual(v7, data.subdata(in: 10..<20))
        let st422 = await status { try await c.call("packPut", params: ["pack": "assets", "file": "bad.bin"], rawBody: Data([1]), headers: ["X-Redx-SHA256": String(repeating: "0", count: 64)]) }
        XCTAssertEqual(st422, 422)
        let png = Data([0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10]) + data.prefix(64)
        try await c.uploadMedia(lib: "art", name: "icon.png", data: png, type: "image/png")
        let v8 = try await c.downloadMedia(lib: "art", name: "icon.png")
        XCTAssertEqual(v8, png)

        #if canImport(FoundationNetworking)
        do { _ = try await c.subscribe("w.red-xai.db:*"); XCTFail("streams should report unsupported here") }
        catch let e as RedXError { XCTAssertEqual(e.code, "unsupported") }
        #else
        let reconnected = ReconnectCounter()
        let s = try await c.subscribe("w.red-xai.db:*", StreamOptions(reconnect: true, minBackoff: 0.05, maxBackoff: 0.2, onReconnect: { reconnected.add() }))
        try await c.set("w.red-xai.db:W[ID=1]", ["A": 1])
        let ev = try await s.next(timeout: 8)
        XCTAssertEqual((ev?.data as? [String: Any])?["A"] as? Double, 1)
        try host.restart()
        for _ in 0..<200 where reconnected.count == 0 { try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertEqual(reconnected.count, 1)
        try await c.set("w.red-xai.db:W[ID=2]", ["A": 2])
        let v9 = try await s.next(timeout: 8)?.path
        XCTAssertEqual(v9, "w.red-xai.db:W[ID=2]")
        s.close()
        let w = try await c.watch("{Watch[]} = w:W[A > $min]", ["min": 4])
        try await c.set("w.red-xai.db:W[ID=3]", ["A": 5])
        let v10 = try await w.next(timeout: 8)
        XCTAssertNotNil(v10)
        w.close()
        #endif

        let v11 = try await admin.clusterStatus().object()["role"]
        XCTAssertNotNil(v11)
        let stPromote = await status { try await admin.promote(confirm: true) }
        XCTAssertGreaterThanOrEqual(stPromote, 400)

        let rq = Connect.newRequest()
        XCTAssertTrue(Connect.link(provider: "gendragoon", rq).hasPrefix("redx://connect?v=1&"))
        let start = try await admin.connectStart(body: ["v": 1, "provider": "gendragoon", "state": rq.state, "pkce_challenge": rq.challenge, "callback": "gendragoon://redx-callback"]).object()
        let ap = try await admin.connectApprove(body: ["request_id": start["request_id"] as! String], confirm: true).object()
        let cbURL = (ap["callback_template"] as! String).replacingOccurrences(of: "{state}", with: rq.state)
        XCTAssertThrowsError(try Connect.parseCallback(cbURL, expectedState: String(repeating: "x", count: rq.state.count)))
        let cb = try Connect.parseCallback(cbURL, expectedState: rq.state)
        let anon = try RedXClient(url: host.url, key: "")
        do { _ = try await anon.exchangeConnectCode(cb.code, Connect.Request(state: rq.state, verifier: String(repeating: "A", count: 43), challenge: rq.challenge)); XCTFail("wrong verifier") }
        catch let e as RedXError { XCTAssertEqual(e.code, "pkce_mismatch") }
        let ex = try await anon.exchangeConnectCode(cb.code, rq, deviceLabel: "swift test")
        let app = try RedXClient(url: host.url, key: ex["key"] as! String, db: (ex["workspace"] as! [String: Any])["db"] as? String)
        try await app.set("save.red-xai.db:S[ID=1]", ["L": 2])
        try await app.connectRevoke()
        let stRevoked = await status { _ = try await app.get("save.red-xai.db:S[ID=1]") }
        XCTAssertEqual(stRevoked, 401)

        let v12 = try await admin.backup().body.count
        XCTAssertGreaterThan(v12, 100)
        try await admin.deleteDatabase(db: "sdksw", confirm: true)
        let v13 = try await admin.listDatabases().text().contains("sdksw")
        XCTAssertFalse(v13)
    }
}

final class ReconnectCounter: @unchecked Sendable {
    private let l = NSLock()
    private var n = 0
    func add() { l.lock(); n += 1; l.unlock() }
    var count: Int { l.lock(); defer { l.unlock() }; return n }
}
