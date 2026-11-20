import Foundation
import CryptoKit
import Network

/// Загрузка подписок (3x-ui, Marzban, Remnawave…): тело — base64 или список ссылок,
/// трафик и срок — из заголовка subscription-userinfo.
enum SubscriptionManager {
    struct UntrustedCertificate: LocalizedError {
        let sha256: String
        var errorDescription: String? { "Сертификат сервера подписки не подтверждён" }
    }

    static func isSubscriptionURL(_ s: String) -> Bool {
        let l = s.lowercased()
        return l.hasPrefix("https://") || l.hasPrefix("http://")
    }

    /// Обновляет поля подписки (трафик, срок, имя) и возвращает её серверы.
    static func fetch(_ sub: inout Subscription) async throws -> (servers: [ServerEntry], errors: [String]) {
        guard let url = URL(string: sub.url) else { throw LinkParser.ParseError("Неверная ссылка на подписку") }
        var req = URLRequest(url: url, timeoutInterval: 20)
        req.setValue("Pon4ik/1.0 v2rayN/7.10", forHTTPHeaderField: "User-Agent")
        req.setValue("*/*", forHTTPHeaderField: "Accept")

        let delegate = PinningDelegate(pinned: sub.pinnedCertSha256)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let data: Data, resp: URLResponse
        do {
            (data, resp) = try await session.data(for: req)
        } catch {
            if let h = delegate.untrustedHash { throw UntrustedCertificate(sha256: h) }
            throw error
        }
        guard let http = resp as? HTTPURLResponse else { throw LinkParser.ParseError("Нет ответа от сервера") }
        guard (200..<300).contains(http.statusCode) else {
            throw LinkParser.ParseError("Сервер подписки ответил \(http.statusCode)")
        }
        readHeaders(http, into: &sub)

        let body = String(data: data, encoding: .utf8) ?? ""
        let text = decodeBody(body)
        if text.trimmingCharacters(in: .whitespaces).hasPrefix("<") {
            throw LinkParser.ParseError("Вместо подписки пришла веб-страница — проверьте ссылку")
        }
        var (servers, errors) = LinkParser.parseMany(text)
        guard !servers.isEmpty else {
            throw LinkParser.ParseError(errors.first.map { "В подписке нет поддерживаемых серверов: \($0)" } ?? "Подписка пустая")
        }
        for i in servers.indices { servers[i].subscriptionId = sub.id }
        if sub.name.isEmpty { sub.name = url.host ?? sub.url }
        sub.lastUpdated = Date()
        sub.lastError = nil
        return (servers, errors)
    }

    static func decodeBody(_ body: String) -> String {
        let t = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.contains("://") { return t }
        return LinkParser.base64Decode(t) ?? t
    }

    private static func readHeaders(_ r: HTTPURLResponse, into sub: inout Subscription) {
        func h(_ name: String) -> String? { r.value(forHTTPHeaderField: name) }
        if let info = h("subscription-userinfo") {
            for part in info.split(separator: ";") {
                let kv = part.split(separator: "=", maxSplits: 1)
                guard kv.count == 2, let n = Int64(kv[1].trimmingCharacters(in: .whitespaces)) else { continue }
                switch kv[0].trimmingCharacters(in: .whitespaces).lowercased() {
                case "upload": sub.upload = n
                case "download": sub.download = n
                case "total": sub.total = n
                case "expire": sub.expire = n
                default: break
                }
            }
        }
        if let s = h("profile-update-interval"), let hours = Int(s), hours > 0 { sub.updateIntervalHours = hours }
        if var title = h("profile-title"), !title.isEmpty {
            if title.lowercased().hasPrefix("base64:") { title = LinkParser.base64Decode(String(title.dropFirst(7))) ?? title }
            sub.name = title.trimmingCharacters(in: .whitespaces)
        }
    }

    /// Проверка сертификата: обычная цепочка доверия либо закреплённый пользователем отпечаток.
    final class PinningDelegate: NSObject, URLSessionDelegate {
        let pinned: String?
        var untrustedHash: String?
        init(pinned: String?) { self.pinned = pinned }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil); return
            }
            var err: CFError?
            if SecTrustEvaluateWithError(trust, &err) {
                completionHandler(.useCredential, URLCredential(trust: trust)); return
            }
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
                let der = SecCertificateCopyData(leaf) as Data
                let hash = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
                if hash == pinned { completionHandler(.useCredential, URLCredential(trust: trust)); return }
                untrustedHash = hash
            }
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

/// Пинг и отпечаток сертификата сервера.
enum NetProbe {
    /// Время TCP-подключения в мс; nil — недоступен.
    static func tcpPing(host: String, port: Int, timeout: TimeInterval = 3) async -> Int? {
        await withCheckedContinuation { cont in
            guard let p = NWEndpoint.Port(rawValue: UInt16(port)) else { cont.resume(returning: nil); return }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
            let start = Date()
            var done = false
            let lock = NSLock()
            func finish(_ v: Int?) {
                lock.lock(); defer { lock.unlock() }
                if done { return }
                done = true
                conn.cancel()
                cont.resume(returning: v)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(Int(Date().timeIntervalSince(start) * 1000))
                case .failed, .cancelled: finish(nil)
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(nil) }
        }
    }

    /// SHA-256 сертификата TLS-сервера (для ссылок с insecure=1).
    static func certSha256(host: String, port: Int) async -> String? {
        guard let url = URL(string: "https://\(LinkParser.isIP(host) && host.contains(":") ? "[\(host)]" : host):\(port)/") else { return nil }
        let delegate = SubscriptionManager.PinningDelegate(pinned: "__capture__")
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: url, timeoutInterval: 6)
        req.httpMethod = "HEAD"
        _ = try? await session.data(for: req)
        return delegate.untrustedHash
    }
}
