import Combine
import Foundation
import NetworkExtension
import SwiftUI

/// Состояние приложения: серверы, подписки, настройки и действия над ними.
@MainActor
final class AppModel: ObservableObject {
    @Published var servers: [ServerEntry] = Storage.load("servers.json", as: [ServerEntry].self) ?? []
    @Published var subs: [Subscription] = Storage.load("subscriptions.json", as: [Subscription].self) ?? []
    @Published var settings: AppSettings = Storage.load("settings.json", as: AppSettings.self) ?? AppSettings()
    @Published var pings: [String: String] = [:]
    @Published var busySubs: Set<String> = []
    @Published var message: String?
    @Published var info: String = ""
    @Published var trustPrompt: (sub: Subscription, sha: String)?

    let vpn = VPNManager()
    private var vpnSink: AnyCancellable?

    init() {
        // экран перерисовывается и при смене статуса VPN
        vpnSink = vpn.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
    }

    var selected: ServerEntry? { servers.first { $0.id == settings.selectedServerId } ?? servers.first }

    // MARK: Подключение

    func toggle() async {
        if vpn.isConnected || vpn.isBusy { vpn.disconnect(); return }
        guard let server = selected else { message = "Добавьте подписку или сервер ниже"; return }
        do {
            var pin: String?
            if server.insecure && !server.isUdp {
                info = "Проверяю сертификат сервера…"
                pin = await NetProbe.certSha256(host: server.address, port: server.port)
            }
            let config = try ConfigBuilder.build(server: server, bypassRu: settings.bypassRu,
                                                 pinnedCertSha256: pin, logPath: "__LOG_PATH__")
            info = ""
            try await vpn.connect(config: config, serverAddress: server.address)
        } catch {
            message = "Не удалось подключиться: \(error.localizedDescription)"
        }
    }

    func select(_ s: ServerEntry) {
        guard s.id != settings.selectedServerId else { return }
        settings.selectedServerId = s.id
        save()
        if vpn.isConnected {
            vpn.disconnect()
            Task { try? await Task.sleep(nanoseconds: 800_000_000); await toggle() }
        }
    }

    func setBypassRu(_ on: Bool) {
        settings.bypassRu = on
        save()
        if vpn.isConnected {
            vpn.disconnect()
            Task { try? await Task.sleep(nanoseconds: 800_000_000); await toggle() }
        }
    }

    // MARK: Добавление

    func add(text: String) async {
        let tokens = text.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
        for url in Set(tokens.filter(SubscriptionManager.isSubscriptionURL)) {
            if !subs.contains(where: { $0.url == url }) { subs.append(Subscription(url: url)) }
            if let s = subs.first(where: { $0.url == url }) { await refresh(s, interactive: true) }
        }
        let (parsed, errors) = LinkParser.parseMany(text)
        for p in parsed where !servers.contains(where: { $0.link == p.link }) { servers.append(p) }
        if settings.selectedServerId == nil { settings.selectedServerId = servers.first?.id }
        save()
        if !errors.isEmpty { message = "Не удалось разобрать:\n" + errors.joined(separator: "\n") }
        await pingAll()
    }

    func delete(_ s: ServerEntry) {
        servers.removeAll { $0.id == s.id }
        if settings.selectedServerId == s.id { settings.selectedServerId = servers.first?.id }
        save()
    }

    func delete(_ sub: Subscription) {
        servers.removeAll { $0.subscriptionId == sub.id }
        subs.removeAll { $0.id == sub.id }
        if selected == nil { settings.selectedServerId = servers.first?.id }
        save()
    }

    // MARK: Подписки

    func refreshDue() async {
        for s in subs where s.isDue { await refresh(s, interactive: false) }
    }

    func refresh(_ sub: Subscription, interactive: Bool) async {
        guard !busySubs.contains(sub.id) else { return }
        busySubs.insert(sub.id)
        defer { busySubs.remove(sub.id) }
        var s = sub
        do {
            let (list, _) = try await SubscriptionManager.fetch(&s)
            let keepLink = selected?.subscriptionId == s.id ? selected?.link : nil
            let keepName = selected?.subscriptionId == s.id ? selected?.name : nil
            servers.removeAll { $0.subscriptionId == s.id }
            servers.insert(contentsOf: list, at: 0)
            if let keepLink, let again = servers.first(where: { $0.link == keepLink }) ?? servers.first(where: { $0.name == keepName }) {
                settings.selectedServerId = again.id
            }
            if selected == nil || !servers.contains(where: { $0.id == settings.selectedServerId }) {
                settings.selectedServerId = servers.first?.id
            }
        } catch let e as SubscriptionManager.UntrustedCertificate where interactive {
            trustPrompt = (s, e.sha256)
        } catch {
            s.lastError = error.localizedDescription
            if interactive { message = "Не удалось загрузить подписку:\n\(error.localizedDescription)" }
        }
        if let i = subs.firstIndex(where: { $0.id == s.id }) { subs[i] = s }
        save()
        await pingAll()
    }

    func trust(_ sub: Subscription, sha: String) async {
        guard let i = subs.firstIndex(where: { $0.id == sub.id }) else { return }
        subs[i].pinnedCertSha256 = sha
        save()
        await refresh(subs[i], interactive: true)
    }

    // MARK: Пинг

    func pingAll() async {
        await withTaskGroup(of: (String, String).self) { group in
            for s in servers {
                group.addTask {
                    if s.isUdp { return (s.id, "UDP") }
                    let ms = await NetProbe.tcpPing(host: s.address, port: s.port)
                    return (s.id, ms.map { "\($0) мс" } ?? "нет связи")
                }
            }
            for await (id, text) in group { pings[id] = text }
        }
    }

    private func save() {
        Storage.save(servers, "servers.json")
        Storage.save(subs, "subscriptions.json")
        Storage.save(settings, "settings.json")
    }
}
