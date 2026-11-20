import NetworkExtension
import Pon4ikCore

/// VPN-расширение: получает туннель от iOS и отдаёт его ядру Xray.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var logPath: String {
        FileManager.default.temporaryDirectory.appendingPathComponent("xray.log").path
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Конфиг приходит при запуске из приложения; при включении из Настроек iOS — берём сохранённый в профиле VPN
        let fromOptions = options?["config"] as? String
        let fromProfile = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["config"] as? String
        guard var config = fromOptions ?? fromProfile else {
            completionHandler(error("Нет настроек сервера — откройте Pon4ik и подключитесь оттуда"))
            return
        }
        config = config.replacingOccurrences(of: "__LOG_PATH__", with: logPath)
        try? FileManager.default.removeItem(atPath: logPath)

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd66:6f6e:7563::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] err in
            guard let self else { return }
            if let err { completionHandler(err); return }
            let fd = Pon4ikcoreFindTunFd()
            guard fd >= 0 else {
                completionHandler(self.error("Не удалось получить туннель iOS"))
                return
            }
            var startError: NSError?
            _ = Pon4ikcoreStart(config, fd, &startError)
            if let startError {
                completionHandler(self.error("Ядро Xray не запустилось: \(startError.localizedDescription)"))
                return
            }
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Pon4ikcoreStop()
        completionHandler()
    }

    /// Приложение спрашивает журнал и версию ядра.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        switch cmd {
        case "log":
            var text = (try? String(contentsOfFile: logPath, encoding: .utf8)) ?? ""
            if text.count > 20000 { text = String(text.suffix(20000)) }
            completionHandler?(("Xray \(Pon4ikcoreVersion())\n" + text).data(using: .utf8))
        default:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        Pon4ikcoreFreeMemory()
        completionHandler()
    }

    private func error(_ text: String) -> NSError {
        NSError(domain: "Pon4ik", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
