import Foundation

/// Разбор ссылок vless://, trojan://, vmess://, ss://, hysteria2:// (hy2://)
/// и превращение их в outbound для ядра Xray. Логика та же, что в Windows/Mac-версиях.
enum LinkParser {
    struct ParseError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
        init(_ m: String) { message = m }
    }

    typealias JSON = [String: Any]

    private static let schemes = ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"]

    static func isLink(_ s: String) -> Bool {
        let l = s.lowercased()
        return schemes.contains { l.hasPrefix($0) }
    }

    static func parse(_ link: String) throws -> ServerEntry {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        var (_, info) = try buildOutbound(trimmed)
        info.link = trimmed
        return info
    }

    /// Разбирает текст со ссылками (по одной в строке).
    static func parseMany(_ text: String) -> (servers: [ServerEntry], errors: [String]) {
        var list: [ServerEntry] = []
        var errors: [String] = []
        for raw in text.components(separatedBy: .whitespacesAndNewlines) where isLink(raw) {
            do { list.append(try parse(raw)) }
            catch { errors.append("\(raw.prefix(40))…: \(error.localizedDescription)") }
        }
        return (list, errors)
    }

    // MARK: - Outbound

    static func buildOutbound(_ link: String) throws -> (JSON, ServerEntry) {
        guard let r = link.range(of: "://") else { throw ParseError("Неверная ссылка") }
        switch link[..<r.lowerBound].lowercased() {
        case "vless": return try vless(link)
        case "trojan": return try trojan(link)
        case "vmess": return try vmess(link)
        case "ss": return try shadowsocks(link)
        case "hysteria2", "hy2": return try hysteria2(link)
        case let s: throw ParseError("Протокол \(s) не поддерживается")
        }
    }

    private static func vless(_ link: String) throws -> (JSON, ServerEntry) {
        let u = try UriParts(link)
        guard !u.user.isEmpty else { throw ParseError("В ссылке нет UUID") }
        var user: JSON = ["id": u.user, "encryption": u.q("encryption", "none")]
        let flow = u.q("flow")
        if !flow.isEmpty { user["flow"] = flow }
        let (stream, label, insecure) = try Self.stream(u.query, address: u.host, defaultSecurity: "none")
        if (stream["security"] as? String) == "none" && !isPrivateHost(u.host) {
            throw ParseError("VLESS без шифрования ядро Xray запрещает для публичных серверов")
        }
        var info = entry(u, "VLESS", label)
        info.insecure = insecure
        return ([
            "protocol": "vless",
            "settings": ["vnext": [["address": u.host, "port": u.port, "users": [user]]]],
            "streamSettings": stream,
        ], info)
    }

    private static func trojan(_ link: String) throws -> (JSON, ServerEntry) {
        let u = try UriParts(link)
        guard !u.user.isEmpty else { throw ParseError("В ссылке нет пароля") }
        let (stream, label, insecure) = try Self.stream(u.query, address: u.host, defaultSecurity: "tls")
        var server: JSON = ["address": u.host, "port": u.port, "password": u.user]
        let flow = u.q("flow")
        if !flow.isEmpty { server["flow"] = flow }
        var info = entry(u, "Trojan", label)
        info.insecure = insecure
        return (["protocol": "trojan", "settings": ["servers": [server]], "streamSettings": stream], info)
    }

    private static func vmess(_ link: String) throws -> (JSON, ServerEntry) {
        let body = String(link.dropFirst("vmess://".count)).components(separatedBy: "#")[0]
        guard let jsonText = base64Decode(body), let data = jsonText.data(using: .utf8),
              let j = try JSONSerialization.jsonObject(with: data) as? JSON else {
            throw ParseError("Неверная ссылка vmess")
        }
        func s(_ k: String) -> String {
            if let v = j[k] as? String { return v }
            if let v = j[k] { return "\(v)" }
            return ""
        }
        let host = s("add")
        guard let port = Int(s("port")) else { throw ParseError("Неверный порт") }
        let net = s("net").isEmpty ? "tcp" : s("net")
        var q: [String: String] = [
            "type": net,
            "security": s("tls") == "tls" ? "tls" : (s("tls") == "reality" ? "reality" : "none"),
            "sni": s("sni"), "host": s("host"), "path": s("path"),
            "headertype": s("type"), "alpn": s("alpn"), "fp": s("fp"),
        ]
        if net == "grpc" { q["servicename"] = s("path") }
        if s("allowInsecure") == "1" || s("allowInsecure") == "true" { q["allowinsecure"] = "1" }
        let (stream, label, insecure) = try Self.stream(q, address: host, defaultSecurity: "none")
        let info = ServerEntry(name: s("ps").isEmpty ? host : s("ps"), proto: "VMess", address: host, port: port,
                               transport: label, insecure: insecure)
        return ([
            "protocol": "vmess",
            "settings": ["vnext": [["address": host, "port": port, "users": [[
                "id": s("id"), "alterId": Int(s("aid")) ?? 0, "security": s("scy").isEmpty ? "auto" : s("scy"),
            ]]]]],
            "streamSettings": stream,
        ], info)
    }

    private static func shadowsocks(_ link: String) throws -> (JSON, ServerEntry) {
        var body = String(link.dropFirst("ss://".count))
        var name = ""
        if let h = body.firstIndex(of: "#") {
            name = String(body[body.index(after: h)...]).removingPercentEncoding ?? ""
            body = String(body[..<h])
        }
        var query: [String: String] = [:]
        if let qi = body.firstIndex(of: "?") {
            query = UriParts.parseQuery(String(body[body.index(after: qi)...]))
            body = String(body[..<qi])
        }
        while body.hasSuffix("/") { body.removeLast() }
        if query["plugin"] != nil { throw ParseError("Плагины Shadowsocks не поддерживаются") }

        var method = "", password = "", hostPort = ""
        if let at = body.lastIndex(of: "@") {
            var userInfo = String(body[..<at]).removingPercentEncoding ?? ""
            if !userInfo.contains(":") { userInfo = base64Decode(userInfo) ?? "" }
            (method, password) = try splitOnce(userInfo, ":")
            hostPort = String(body[body.index(after: at)...])
        } else {
            guard let dec = base64Decode(body), let a = dec.lastIndex(of: "@") else { throw ParseError("Неверная ссылка ss") }
            (method, password) = try splitOnce(String(dec[..<a]), ":")
            hostPort = String(dec[dec.index(after: a)...])
        }
        let (host, port) = try UriParts.splitHostPort(hostPort)
        let info = ServerEntry(name: name.isEmpty ? host : name, proto: "Shadowsocks", address: host, port: port, transport: method)
        return ([
            "protocol": "shadowsocks",
            "settings": ["servers": [["address": host, "port": port, "method": method, "password": password]]],
        ], info)
    }

    private static func hysteria2(_ link: String) throws -> (JSON, ServerEntry) {
        let u = try UriParts(link, allowPortRange: true)
        var tls: JSON = ["alpn": ["h3"]]
        let sni = u.q("sni")
        if !sni.isEmpty { tls["serverName"] = sni }
        else if !isIP(u.host) { tls["serverName"] = u.host }
        let pin = u.q("pinsha256").replacingOccurrences(of: ":", with: "").lowercased()
        if !pin.isEmpty { tls["pinnedPeerCertSha256"] = pin }
        let insecure = pin.isEmpty && (u.q("insecure") == "1" || u.q("allowinsecure") == "1")

        var stream: JSON = [
            "network": "hysteria",
            "hysteriaSettings": ["version": 2, "auth": u.user],
            "security": "tls",
            "tlsSettings": tls,
        ]
        let obfs = u.q("obfs")
        if obfs == "salamander" {
            stream["finalmask"] = ["udp": [["type": "salamander", "settings": ["password": u.q("obfs-password")]]]]
        } else if !obfs.isEmpty {
            throw ParseError("Маскировка \(obfs) не поддерживается")
        }
        var info = entry(u, "Hysteria2", obfs == "salamander" ? "QUIC · Salamander" : "QUIC")
        info.isUdp = true
        info.insecure = insecure
        return ([
            "protocol": "hysteria",
            "settings": ["version": 2, "address": u.host, "port": u.port],
            "streamSettings": stream,
        ], info)
    }

    // MARK: - Транспорт и шифрование

    private static func stream(_ q: [String: String], address: String, defaultSecurity: String) throws -> (JSON, String, Bool) {
        func Q(_ k: String, _ d: String = "") -> String {
            if let v = q[k.lowercased()], !v.isEmpty { return v }
            return d
        }
        var network = Q("type", "tcp").lowercased()
        if network == "splithttp" { network = "xhttp" }
        var security = Q("security", defaultSecurity).lowercased()
        if security.isEmpty { security = "none" }

        var s: JSON = ["network": network, "security": security]
        let host = Q("host")
        let path = Q("path", "/")
        func obj(_ pairs: [(String, String)]) -> JSON {
            var o: JSON = [:]
            for (k, v) in pairs where !v.isEmpty { o[k] = v }
            return o
        }

        var netLabel: String
        switch network {
        case "tcp", "raw":
            netLabel = "TCP"
            if Q("headerType") == "http" {
                s["tcpSettings"] = ["header": [
                    "type": "http",
                    "request": ["path": [path], "headers": ["Host": host.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }]],
                ]]
            }
        case "ws":
            netLabel = "WebSocket"
            s["wsSettings"] = obj([("path", path), ("host", host)])
        case "httpupgrade":
            netLabel = "HTTPUpgrade"
            s["httpupgradeSettings"] = obj([("path", path), ("host", host)])
        case "grpc":
            netLabel = "gRPC"
            var g: JSON = ["serviceName": Q("serviceName", Q("path"))]
            if Q("mode") == "multi" { g["multiMode"] = true }
            if !Q("authority").isEmpty { g["authority"] = Q("authority") }
            s["grpcSettings"] = g
        case "xhttp":
            netLabel = "xHTTP"
            var x = obj([("path", path), ("host", host)])
            x["mode"] = Q("mode", "auto")
            let extra = Q("extra")
            if !extra.isEmpty, let d = extra.data(using: .utf8), let e = try? JSONSerialization.jsonObject(with: d) {
                x["extra"] = e
            }
            s["xhttpSettings"] = x
        case "kcp", "mkcp":
            netLabel = "mKCP"
            s["network"] = "kcp"
            s["kcpSettings"] = Q("seed").isEmpty ? [:] as JSON : ["seed": Q("seed")]
        default:
            throw ParseError("Транспорт «\(network)» не поддерживается")
        }

        let sni = Q("sni", Q("peer"))
        let fp = Q("fp")
        var insecure = false
        var secLabel: String
        switch security {
        case "tls":
            secLabel = "TLS"
            var tls: JSON = [:]
            if !sni.isEmpty { tls["serverName"] = sni }
            else if !host.isEmpty && network != "tcp" { tls["serverName"] = String(host.split(separator: ",")[0]) }
            else if !isIP(address) { tls["serverName"] = address }
            if !fp.isEmpty { tls["fingerprint"] = fp }
            let alpn = Q("alpn")
            if !alpn.isEmpty { tls["alpn"] = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
            let pcs = Q("pcs").replacingOccurrences(of: ":", with: "").lowercased()
            if !pcs.isEmpty { tls["pinnedPeerCertSha256"] = pcs }
            else if Q("allowInsecure") == "1" || Q("insecure") == "1" { insecure = true }
            s["tlsSettings"] = tls
        case "reality":
            secLabel = "Reality"
            guard !Q("pbk").isEmpty else { throw ParseError("Нет параметра pbk (публичный ключ REALITY)") }
            var r: JSON = [
                "serverName": sni, "fingerprint": fp.isEmpty ? "chrome" : fp,
                "publicKey": Q("pbk"), "shortId": Q("sid"),
            ]
            if !Q("spx").isEmpty { r["spiderX"] = Q("spx") }
            s["realitySettings"] = r
        case "none":
            secLabel = "без шифрования"
        default:
            throw ParseError("Шифрование «\(security)» не поддерживается")
        }
        let label = "\(netLabel) · \(secLabel)" + (Q("flow").contains("vision") ? " · Vision" : "")
        return (s, label, insecure)
    }

    // MARK: - Помощники

    private static func entry(_ u: UriParts, _ proto: String, _ transport: String) -> ServerEntry {
        ServerEntry(name: u.fragment.trimmingCharacters(in: .whitespaces).isEmpty ? u.host : u.fragment.trimmingCharacters(in: .whitespaces),
                    proto: proto, address: u.host, port: u.port, transport: transport)
    }

    static func isIP(_ s: String) -> Bool {
        var a4 = in_addr(), a6 = in6_addr()
        return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
    }

    static func isPrivateHost(_ host: String) -> Bool {
        if host == "localhost" { return true }
        let p = host.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return host.hasPrefix("fd") || host.hasPrefix("fe80") || host == "::1" }
        return p[0] == 10 || p[0] == 127 || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 168)
    }

    private static func splitOnce(_ s: String, _ c: Character) throws -> (String, String) {
        guard let i = s.firstIndex(of: c) else { throw ParseError("Неверный формат") }
        return (String(s[..<i]), String(s[s.index(after: i)...]))
    }

    static func base64Decode(_ s: String) -> String? {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        while t.count % 4 != 0 { t += "=" }
        guard let d = Data(base64Encoded: t) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    // MARK: - Разбор URI

    struct UriParts {
        var user = "", host = "", fragment = ""
        var port = 0
        var query: [String: String] = [:]   // ключи в нижнем регистре

        func q(_ k: String, _ d: String = "") -> String {
            if let v = query[k.lowercased()], !v.isEmpty { return v }
            return d
        }

        init(_ link: String, allowPortRange: Bool = false) throws {
            guard let r = link.range(of: "://") else { throw ParseError("Неверная ссылка") }
            var body = String(link[r.upperBound...])
            if let h = body.firstIndex(of: "#") {
                fragment = String(body[body.index(after: h)...]).removingPercentEncoding ?? ""
                body = String(body[..<h])
            }
            if let qi = body.firstIndex(of: "?") {
                query = Self.parseQuery(String(body[body.index(after: qi)...]))
                body = String(body[..<qi])
            }
            while body.hasSuffix("/") { body.removeLast() }
            if let at = body.lastIndex(of: "@") {
                user = String(body[..<at]).removingPercentEncoding ?? String(body[..<at])
                body = String(body[body.index(after: at)...])
            }
            (host, port) = try Self.splitHostPort(body, allowPortRange: allowPortRange)
        }

        static func splitHostPort(_ hp: String, allowPortRange: Bool = false) throws -> (String, Int) {
            var host: String, portStr: String
            if hp.hasPrefix("[") {
                guard let end = hp.firstIndex(of: "]") else { throw ParseError("Неверный IPv6-адрес") }
                host = String(hp[hp.index(after: hp.startIndex)..<end])
                let rest = hp[hp.index(after: end)...]
                portStr = rest.hasPrefix(":") ? String(rest.dropFirst()) : "443"
            } else if let c = hp.lastIndex(of: ":") {
                host = String(hp[..<c]); portStr = String(hp[hp.index(after: c)...])
            } else {
                host = hp; portStr = "443"
            }
            if allowPortRange { portStr = String(portStr.split(whereSeparator: { $0 == "," || $0 == "-" }).first ?? "") }
            guard let port = Int(portStr), (1...65535).contains(port) else { throw ParseError("Неверный порт") }
            guard !host.isEmpty else { throw ParseError("Нет адреса сервера") }
            return (host, port)
        }

        static func parseQuery(_ q: String) -> [String: String] {
            var d: [String: String] = [:]
            for part in q.split(separator: "&") {
                let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                let v = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
                d[k.lowercased()] = v
            }
            return d
        }
    }
}
