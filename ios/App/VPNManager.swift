import Foundation
import NetworkExtension

/// Управление системным VPN-профилем Pon4ik.
@MainActor
final class VPNManager: ObservableObject {
    static let tunnelBundleId = (Bundle.main.bundleIdentifier ?? "app.pon4ik.client") + ".tunnel"

    @Published private(set) var status: NEVPNStatus = .disconnected
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] n in
            guard let conn = n.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.status = conn.status }
        }
        Task { await load() }
    }

    func load() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = all.first
        status = manager?.connection.status ?? .disconnected
    }

    var isConnected: Bool { status == .connected }
    var isBusy: Bool { status == .connecting || status == .disconnecting || status == .reasserting }

    /// Сохраняет профиль VPN (при первом разе iOS спросит разрешение) и подключается.
    func connect(config: String, serverAddress: String) async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleId
        proto.serverAddress = serverAddress
        proto.providerConfiguration = ["config": config]
        proto.disconnectOnSleep = false
        m.protocolConfiguration = proto
        m.localizedDescription = "Pon4ik"
        m.isEnabled = true
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
        try m.connection.startVPNTunnel(options: ["config": config as NSString])
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Журнал ядра из VPN-расширения.
    func fetchLog() async -> String {
        guard let session = manager?.connection as? NETunnelProviderSession, status != .invalid else {
            return "VPN ещё не запускался"
        }
        return await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(Data("log".utf8)) { data in
                    cont.resume(returning: data.flatMap { String(data: $0, encoding: .utf8) } ?? "Журнал пуст (VPN не подключён)")
                }
            } catch {
                cont.resume(returning: "Не удалось получить журнал: \(error.localizedDescription)")
            }
        }
    }
}
