import Foundation

/// Конфиг Xray для iOS: вход — системный VPN-туннель (tun), выход — выбранный сервер.
/// Гео-базы на iPhone не грузим (лимит памяти VPN-расширения ~50 МБ), российские сайты — по доменам.
enum ConfigBuilder {
    /// Адрес «DNS-сервера» внутри туннеля: его запросы перехватывает Xray.
    static let tunDNS = "198.18.0.2"

    static let ruDomains: [String] = [
        "domain:ru", "domain:su", "domain:xn--p1ai", "domain:xn--d1acj3b", "domain:moscow", "domain:xn--80adxhks", "domain:tatar",
        "domain:yandex.com", "domain:yandex.net", "domain:yastatic.net", "domain:yandexcloud.net", "domain:ya.cc",
        "domain:vk.com", "domain:vk.me", "domain:userapi.com", "domain:vkuser.net", "domain:vk-cdn.net", "domain:mycdn.me",
        "domain:mvk.com", "domain:vkvideo.ru", "domain:okcdn.ru",
        "domain:sberbank.com", "domain:tinkoff.com", "domain:tbank.com", "domain:alfabank.com", "domain:vtb.com",
        "domain:ozon.com", "domain:wildberries.com", "domain:wbbasket.ru", "domain:wbstatic.net", "domain:avito.st",
        "domain:kinopoisk.com", "domain:rutube.com", "domain:dzen.com", "domain:2gis.com", "domain:kaspersky.com",
    ]

    static let privateCIDRs = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
        "fc00::/7", "fe80::/10",
    ]

    static func build(server: ServerEntry, bypassRu: Bool, pinnedCertSha256: String? = nil, logPath: String) throws -> String {
        var (proxy, _) = try LinkParser.buildOutbound(server.link)
        proxy["tag"] = "proxy"
        if let pin = pinnedCertSha256,
           var stream = proxy["streamSettings"] as? [String: Any],
           var tls = stream["tlsSettings"] as? [String: Any] {
            tls["pinnedPeerCertSha256"] = pin
            stream["tlsSettings"] = tls
            proxy["streamSettings"] = stream
        }

        var rules: [[String: Any]] = [
            // DNS-запросы из туннеля отвечает сам Xray (через свой DNS, который ходит через сервер)
            ["type": "field", "inboundTag": ["tun"], "port": "53", "outboundTag": "dns-out"],
            ["type": "field", "ip": privateCIDRs, "outboundTag": "direct"],
        ]
        rules.append(LinkParser.isIP(server.address)
            ? ["type": "field", "ip": [server.address], "outboundTag": "direct"]
            : ["type": "field", "domain": ["full:" + server.address], "outboundTag": "direct"])
        if bypassRu {
            rules.append(["type": "field", "domain": ruDomains, "outboundTag": "direct"])
        }

        let cfg: [String: Any] = [
            "log": ["loglevel": "warning", "error": logPath],
            "dns": ["servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"],
            "inbounds": [[
                "tag": "tun", "protocol": "tun", "port": 0,
                "settings": ["name": "utun", "mtu": 1500],
                "sniffing": ["enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true],
            ]],
            "outbounds": [
                proxy,
                ["tag": "direct", "protocol": "freedom"],
                ["tag": "dns-out", "protocol": "dns"],
                ["tag": "block", "protocol": "blackhole"],
            ],
            "routing": ["domainStrategy": "AsIs", "rules": rules],
            "policy": ["levels": ["0": ["bufferSize": 4]]],   // поменьше буферы — экономим память
        ]
        let data = try JSONSerialization.data(withJSONObject: cfg, options: [.sortedKeys])
        return String(data: data, encoding: .utf8)!
    }
}
