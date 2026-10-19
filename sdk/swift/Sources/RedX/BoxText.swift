import Foundation

public struct BoxTextError: Error, CustomStringConvertible {
    public let message: String
    public let offset: Int
    public var description: String { "box text: \(message) (at offset \(offset))" }
}

/// Decoder for the Box text the host returns, with the host's JSON mapping (docs/box-grammar.md): String,
/// Double, Bool, NELL (NSNull), ;[a, b]: ([Any]), [ {K[]} = v, {K[ID=2]} = w ] ([String: Any] with keys "K"
/// and "K[ID=2]"), links (["$link": text]). TTL markers are skipped.
public enum BoxText {
    public static func decode(_ text: String) throws -> Any {
        var r = Reader(Array(text.utf8))
        let v = try r.value(0)
        try r.ttl()
        if r.peek() != nil { throw r.fail("unexpected text after the value") }
        return v
    }

    struct Reader {
        let s: [UInt8]
        var i = 0
        init(_ s: [UInt8]) { self.s = s }
        func fail(_ m: String) -> BoxTextError { BoxTextError(message: m, offset: i) }
        func at(_ j: Int) -> UInt8? { j < s.count ? s[j] : nil }
        mutating func ws() throws {
            while let c = at(i) {
                if c == 32 || c == 9 || c == 10 || c == 13 { i += 1 } else if c == 60 && at(i + 1) == 60 {
                    var j = i + 2
                    while j + 1 < s.count && !(s[j] == 62 && s[j + 1] == 62) { j += 1 }
                    if j + 1 >= s.count { throw fail("unterminated comment") }
                    i = j + 2
                } else { return }
            }
        }
        mutating func peek() -> UInt8? { try? ws(); return at(i) }
        mutating func eat(_ c: Character) -> Bool { if peek() == c.asciiValue { i += 1; return true }; return false }
        mutating func expect(_ c: Character) throws { if !eat(c) { throw fail("expected '\(c)'") } }
        static func idStart(_ c: UInt8?) -> Bool { guard let c = c else { return false }; return c == 95 || (c | 0x20 >= 97 && c | 0x20 <= 122) || c >= 0x80 }
        static func idPart(_ c: UInt8?) -> Bool { guard let c = c else { return false }; return idStart(c) || (c >= 48 && c <= 57) || c == 45 }

        mutating func str() throws -> String {
            let st = i
            guard at(i) == 34 else { throw fail("expected a string") }
            i += 1
            while true {
                guard let c = at(i) else { throw fail("unterminated string") }
                if c == 92 { i += 2; continue }
                i += 1
                if c == 34 { break }
            }
            let lit = Data(s[st..<i])
            guard let arr = try? JSONSerialization.jsonObject(with: Data("[".utf8) + lit + Data("]".utf8)) as? [String], let v = arr.first else {
                i = st; throw fail("bad string literal")
            }
            return v
        }

        mutating func ident() throws -> String {
            let st = i
            guard Reader.idStart(at(i)) else { throw fail("expected an identifier") }
            while Reader.idPart(at(i)) { i += 1 }
            return String(decoding: s[st..<i], as: UTF8.self)
        }

        mutating func ttl() throws {
            guard peek() == 40 else { return }
            guard let e = s[i...].firstIndex(of: 41) else { throw fail("bad TTL marker") }
            let inner = String(decoding: s[(i + 1)..<e], as: UTF8.self).trimmingCharacters(in: .whitespaces)
            let body = inner.hasPrefix("~") ? String(inner.dropFirst()) : inner
            let parts = body.split(separator: "@", omittingEmptySubsequences: false)
            guard !parts.isEmpty, parts.count <= 2, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) else { throw fail("bad TTL marker") }
            i = e + 1
            if at(i) == 42 { i += 1 }
        }

        mutating func linkText(_ start: Int) throws -> String {
            var depth = 0
            i = start
            while let c = at(i) {
                if c == 34 { _ = try str(); continue }
                if c == 91 { depth += 1 } else if c == 93 || c == 125 { if depth == 0 { break }; depth -= 1 } else if (c == 44 || c == 59) && depth == 0 { break }
                i += 1
            }
            return String(decoding: s[start..<i], as: UTF8.self).trimmingCharacters(in: .whitespaces)
        }

        mutating func value(_ depth: Int) throws -> Any {
            if depth > 200 { throw fail("nested too deeply") }
            guard let c = peek() else { throw fail("unexpected end of input") }
            switch c {
            case 34:
                let st = i
                let v = try str()
                var j = i
                while let w = at(j), w == 32 || w == 9 || w == 10 || w == 13 { j += 1 }
                if at(j) == 58 && Reader.idStart(at(j + 1)) { return ["$link": try linkText(st)] }
                return v
            case 59:
                i += 1
                try expect("[")
                var arr: [Any] = []
                if !eat("]") {
                    repeat { arr.append(try value(depth + 1)) } while eat(",")
                    try expect("]")
                }
                try expect(":")
                return arr
            case 91:
                i += 1
                return try body(depth + 1)
            case 45, 48...57:
                let st = i
                if at(i) == 45 { i += 1 }
                while let d = at(i), d >= 48 && d <= 57 { i += 1 }
                if at(i) == 46 { i += 1; while let d = at(i), d >= 48 && d <= 57 { i += 1 } }
                if at(i) == 101 || at(i) == 69 { i += 1; if at(i) == 43 || at(i) == 45 { i += 1 }; while let d = at(i), d >= 48 && d <= 57 { i += 1 } }
                guard let n = Double(String(decoding: s[st..<i], as: UTF8.self)) else { throw fail("expected a number") }
                return n
            default:
                if Reader.idStart(c) {
                    let w = try ident().uppercased()
                    if w == "TRUE" { return true }
                    if w == "FALSE" { return false }
                    if w == "NELL" { return NSNull() }
                    throw fail("unexpected word \(w)")
                }
                throw fail("unexpected character")
            }
        }

        mutating func body(_ depth: Int) throws -> [String: Any] {
            var out: [String: Any] = [:]
            while !eat("]") {
                try expect("{")
                var name = try ident()
                var id: String?
                if eat("[") {
                    while !eat("]") {
                        try ws()
                        var j = i
                        let save = i
                        if at(j) == 73 || at(j) == 105, at(j + 1) == 68 || at(j + 1) == 100 { // ID=
                            j += 2
                            while at(j) == 32 { j += 1 }
                            if at(j) == 61 { j += 1; while at(j) == 32 { j += 1 } } else { j = save }
                        }
                        let ns = j
                        if at(j) == 45 { j += 1 }
                        while let d = at(j), d >= 48 && d <= 57 { j += 1 }
                        var k = j
                        while at(k) == 32 { k += 1 }
                        if id == nil, j > ns + (at(ns) == 45 ? 1 : 0), at(k) == 44 || at(k) == 93 {
                            id = String(decoding: s[ns..<j], as: UTF8.self)
                            i = k
                        } else {
                            i = save
                            while let c = at(i), c != 44 && c != 93 { if c == 34 { _ = try str() } else { i += 1 } }
                        }
                        _ = eat(",")
                    }
                }
                try expect("}")
                try expect("=")
                let v = try value(depth + 1)
                try ttl()
                if let id = id { name += "[ID=\(id)]" }
                out[name] = v
                if !eat(",") { _ = eat(";") }
            }
            return out
        }
    }
}
