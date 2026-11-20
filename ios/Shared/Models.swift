import Foundation

/// Один сервер = одна ссылка (vless://, trojan://, vmess://, ss://, hysteria2://).
struct ServerEntry: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String = ""
    var link: String = ""
    var proto: String = ""
    var address: String = ""
    var port: Int = 0
    /// Например «TCP · TLS» или «QUIC · Salamander».
    var transport: String = ""
    var isUdp: Bool = false
    /// Ссылка просит не проверять сертификат (insecure=1).
    var insecure: Bool = false
    /// Из какой подписки сервер; nil — добавлен вручную.
    var subscriptionId: String?

    var details: String { "\(proto) · \(transport)" }
}

/// Подписка (ссылка https://… от панели 3x-ui, Marzban, Remnawave и т. п.).
struct Subscription: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var url: String = ""
    var name: String = ""
    var upload: Int64 = 0
    var download: Int64 = 0
    var total: Int64 = 0          // 0 = безлимит
    var expire: Int64 = 0         // unix-время, 0 = бессрочно
    var updateIntervalHours: Int = 12
    var lastUpdated: Date?
    var lastError: String?
    /// SHA-256 сертификата панели, которому пользователь разрешил доверять.
    var pinnedCertSha256: String?

    var traffic: String {
        "Трафик: \(Self.formatBytes(upload + download)) из \(total > 0 ? Self.formatBytes(total) : "∞")"
    }

    var expireText: String {
        guard expire > 0 else { return "бессрочно" }
        let d = Date(timeIntervalSince1970: TimeInterval(expire))
        let f = DateFormatter(); f.dateFormat = "dd.MM.yyyy"
        return d < Date() ? "истекла \(f.string(from: d))" : "до \(f.string(from: d))"
    }

    var usedFraction: Double {
        total > 0 ? min(1, Double(upload + download) / Double(total)) : 0
    }

    var status: String {
        if let e = lastError { return "ошибка: \(e)" }
        if let t = lastUpdated {
            let f = DateFormatter(); f.dateFormat = "dd.MM HH:mm"
            return "обновлено \(f.string(from: t))"
        }
        return ""
    }

    var isDue: Bool {
        guard let t = lastUpdated else { return true }
        return Date().timeIntervalSince(t) > Double(max(1, updateIntervalHours)) * 3600
    }

    static func formatBytes(_ b: Int64) -> String {
        let units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
        var v = Double(b); var i = 0
        while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
        return i == 0 ? String(format: "%.0f %@", v, units[i]) : String(format: "%.2f %@", v, units[i])
            .replacingOccurrences(of: ".00 ", with: " ")
    }
}

struct AppSettings: Codable {
    var selectedServerId: String?
    var bypassRu: Bool = true
}

/// Простое хранилище в Documents приложения.
enum Storage {
    private static var dir: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    static func load<T: Decodable>(_ name: String, as: T.Type) -> T? {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent(name)) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    static func save<T: Encodable>(_ value: T, _ name: String) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: dir.appendingPathComponent(name), options: .atomic)
    }
}
