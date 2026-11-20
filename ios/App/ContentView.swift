import SwiftUI
import NetworkExtension

private extension Color {
    static let choco = Color(red: 0x4A / 255, green: 0x26 / 255, blue: 0x18 / 255)
    static let pink = Color(red: 0xE8 / 255, green: 0x50 / 255, blue: 0x8A / 255)
    static let muted = Color(red: 0x8C / 255, green: 0x6E / 255, blue: 0x78 / 255)
    static let line = Color(red: 0xF6 / 255, green: 0xDC / 255, blue: 0xE6 / 255)
    static let rays = Color(red: 0xFF / 255, green: 0xEE / 255, blue: 0xF4 / 255)
    static let offRed = Color(red: 0xE2 / 255, green: 0x33 / 255, blue: 0x5F / 255)
    static let onGreen = Color(red: 0x17 / 255, green: 0xA3 / 255, blue: 0x4A / 255)
    static let card = Color(red: 0xFF / 255, green: 0xF8 / 255, blue: 0xFB / 255)
    static let cardSel = Color(red: 0xFF / 255, green: 0xE8 / 255, blue: 0xF1 / 255)
}

struct ContentView: View {
    @StateObject private var model = AppModel()
    @State private var showAdd = false
    @State private var showLog = false

    var body: some View {
        ZStack {
            Color.white.ignoresSafeArea()
            RaysView().ignoresSafeArea()

            ScrollView {
                VStack(spacing: 18) {
                    header
                    powerButton.padding(.top, 8)
                    statusBlock
                    if !model.subs.isEmpty { subscriptions }
                    serversBlock
                    addButton
                    Toggle(isOn: Binding(get: { model.settings.bypassRu }, set: { model.setBypassRu($0) })) {
                        Text("Российские сайты — напрямую, мимо VPN").font(.subheadline).foregroundColor(.muted)
                    }
                    .tint(.pink)
                    footer
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
            }
        }
        .sheet(isPresented: $showAdd) { AddSheet { text in Task { await model.add(text: text) } } }
        .sheet(isPresented: $showLog) { LogSheet(vpn: model.vpn) }
        .alert("Pon4ik", isPresented: Binding(get: { model.message != nil }, set: { if !$0 { model.message = nil } })) {
            Button("OK", role: .cancel) {}
        } message: { Text(model.message ?? "") }
        .alert("Сертификат не подтверждён", isPresented: Binding(get: { model.trustPrompt != nil }, set: { if !$0 { model.trustPrompt = nil } })) {
            Button("Нет", role: .cancel) {}
            Button("Доверять") {
                if let p = model.trustPrompt { Task { await model.trust(p.sub, sha: p.sha) } }
            }
        } message: {
            Text("Сертификат сервера подписки не подтверждён (обычно это самоподписанный сертификат панели).\n\nОтпечаток SHA-256:\n\(model.trustPrompt?.sha ?? "")\n\nЕсли это ваш сервер — нажмите «Доверять».")
        }
        .task {
            await model.pingAll()
            await model.refreshDue()
        }
        .preferredColorScheme(.light)
    }

    // MARK: Шапка

    private var header: some View {
        HStack(spacing: 12) {
            Image("Avatar")
                .resizable().scaledToFill()
                .frame(width: 62, height: 62)
                .clipShape(Circle())
                .overlay(Circle().stroke(Color.pink, lineWidth: 3))
            VStack(alignment: .leading, spacing: 2) {
                (Text("Pon").foregroundColor(.choco) + Text("4").foregroundColor(.pink) + Text("ik").foregroundColor(.choco))
                    .font(.system(size: 32, weight: .black))
                HStack(spacing: 4) {
                    ForEach([Color(red: 0.95, green: 0.48, blue: 0.67), Color(red: 0.5, green: 0.82, blue: 1),
                             Color(red: 1, green: 0.85, blue: 0.3), Color(red: 0.61, green: 0.89, blue: 0.56), .choco], id: \.self) { c in
                        Capsule().fill(c).frame(width: 12, height: 4)
                    }
                }
            }
            Spacer()
            Text("VPN").font(.caption.bold()).foregroundColor(.white)
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(LinearGradient(colors: [Color(red: 0.95, green: 0.48, blue: 0.67), Color(red: 0.84, green: 0.24, blue: 0.47)],
                                           startPoint: .top, endPoint: .bottom))
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }

    // MARK: Кнопка и статус

    private var stateColor: Color {
        switch model.vpn.status {
        case .connected: return .onGreen
        case .connecting, .reasserting, .disconnecting: return .orange
        default: return .offRed
        }
    }

    private var powerButton: some View {
        Button { Task { await model.toggle() } } label: {
            ZStack {
                Circle().fill(Color(red: 0.97, green: 0.73, blue: 0.82))
                Circle()
                    .fill(RadialGradient(colors: [.white, Color(red: 1, green: 0.96, blue: 0.98), Color(red: 0.97, green: 0.87, blue: 0.91)],
                                         center: UnitPoint(x: 0.4, y: 0.3), startRadius: 0, endRadius: 110))
                    .padding(7)
                    .shadow(color: Color.choco.opacity(0.18), radius: 10, y: 3)
                PowerIcon().stroke(stateColor, style: StrokeStyle(lineWidth: 7, lineCap: .round))
                    .frame(width: 58, height: 62)
            }
            .frame(width: 196, height: 196)
        }
        .buttonStyle(.plain)
    }

    private var statusBlock: some View {
        VStack(spacing: 2) {
            HStack(spacing: 8) {
                Circle().fill(model.vpn.status == .connected ? Color.onGreen : Color(red: 0.77, green: 0.65, blue: 0.7))
                    .frame(width: 9, height: 9)
                Text(statusText).font(.system(size: 22, weight: .bold)).italic().foregroundColor(.choco)
            }
            Text(subStatus).font(.subheadline).foregroundColor(.muted).multilineTextAlignment(.center)
        }
    }

    private var statusText: String {
        switch model.vpn.status {
        case .connected: return "Подключено"
        case .connecting, .reasserting: return "Подключение…"
        case .disconnecting: return "Отключение…"
        default: return "Отключено"
        }
    }

    private var subStatus: String {
        if !model.info.isEmpty { return model.info }
        guard let s = model.selected else { return "Добавьте подписку или сервер ниже" }
        return model.vpn.status == .connected ? "\(s.name) · \(s.proto)" : "Нажмите, чтобы подключиться"
    }

    // MARK: Подписки

    private var subscriptions: some View {
        VStack(spacing: 8) {
            ForEach(model.subs) { sub in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("ПОДПИСКА").font(.system(size: 10, weight: .bold)).foregroundColor(.pink)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Color.cardSel).clipShape(RoundedRectangle(cornerRadius: 5))
                        Text(sub.name.isEmpty ? sub.url : sub.name).font(.system(size: 14, weight: .bold))
                            .foregroundColor(.choco).lineLimit(1)
                        Spacer()
                        Button(model.busySubs.contains(sub.id) ? "…" : "обновить") {
                            Task { await model.refresh(sub, interactive: true) }
                        }.font(.subheadline).foregroundColor(.pink)
                        Button { model.delete(sub) } label: { Image(systemName: "xmark").foregroundColor(.muted.opacity(0.6)) }
                    }
                    ProgressView(value: sub.usedFraction).tint(.pink)
                    Text("\(sub.traffic)  ·  срок: \(sub.expireText)").font(.caption).foregroundColor(.muted)
                    if !sub.status.isEmpty { Text(sub.status).font(.caption2).foregroundColor(.muted.opacity(0.7)) }
                }
                .padding(14)
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.line))
                .shadow(color: .black.opacity(0.05), radius: 8, y: 1)
            }
        }
    }

    // MARK: Серверы

    private var serversBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("СЕРВЕРЫ").font(.system(size: 12, weight: .black)).italic().foregroundColor(.choco)
                Spacer()
                Button("обновить пинг") { Task { await model.pingAll() } }.font(.subheadline).foregroundColor(.pink)
            }
            VStack(spacing: 6) {
                if model.servers.isEmpty {
                    VStack(spacing: 10) {
                        Image("Mascot").resizable().scaledToFill().frame(width: 150, height: 150)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .shadow(color: Color.choco.opacity(0.15), radius: 8, y: 2)
                        Text("Серверов пока нет.\nВставьте ссылку на подписку или ссылки на серверы.")
                            .font(.subheadline).foregroundColor(.muted).multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 18)
                } else {
                    ForEach(model.servers) { s in
                        let sel = s.id == model.selected?.id
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.name).font(.system(size: 15, weight: .semibold)).foregroundColor(.choco).lineLimit(1)
                                Text(s.details).font(.caption).foregroundColor(.muted).lineLimit(1)
                            }
                            Spacer()
                            Text(model.pings[s.id] ?? "—").font(.subheadline).foregroundColor(.muted)
                            if s.subscriptionId == nil {
                                Button { model.delete(s) } label: { Image(systemName: "xmark").foregroundColor(.muted.opacity(0.6)) }
                                    .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 10)
                        .background(sel ? Color.cardSel : Color.card)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(sel ? Color.pink : Color.line, lineWidth: 1.5))
                        .contentShape(Rectangle())
                        .onTapGesture { model.select(s) }
                    }
                }
            }
            .padding(10)
            .background(Color.white)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.line))
        }
    }

    private var addButton: some View {
        Button { showAdd = true } label: {
            Text("+ Добавить подписку или сервер").font(.system(size: 15, weight: .semibold)).foregroundColor(.pink)
                .frame(maxWidth: .infinity).padding(.vertical, 14)
                .background(Color(red: 1, green: 0.98, blue: 0.99))
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(red: 0.95, green: 0.65, blue: 0.78),
                                                                   style: StrokeStyle(lineWidth: 1.5, dash: [4, 3])))
        }
    }

    private var footer: some View {
        HStack {
            Text("Pon4ik").font(.footnote.weight(.semibold)).foregroundColor(.muted)
            Spacer()
            Button("Журнал") { showLog = true }.font(.footnote.weight(.semibold)).foregroundColor(.pink)
        }
        .padding(.top, 6)
    }
}

/// Значок кнопки питания.
struct PowerIcon: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let c = CGPoint(x: r.midX, y: r.midY + r.height * 0.06)
        let rad = min(r.width, r.height) * 0.46
        p.addArc(center: c, radius: rad, startAngle: .degrees(-50), endAngle: .degrees(230), clockwise: false)
        p.move(to: CGPoint(x: r.midX, y: r.minY))
        p.addLine(to: CGPoint(x: r.midX, y: r.midY))
        return p
    }
}

/// Расходящиеся розовые лучи на фоне.
struct RaysView: View {
    var body: some View {
        Canvas { ctx, size in
            let center = CGPoint(x: size.width / 2, y: 300)
            let n = 36, r = 2000.0
            for i in stride(from: 0, to: n, by: 2) {
                let a1 = Double(i) * 2 * .pi / Double(n), a2 = Double(i + 1) * 2 * .pi / Double(n)
                var p = Path()
                p.move(to: center)
                p.addLine(to: CGPoint(x: center.x + r * cos(a1), y: center.y + r * sin(a1)))
                p.addLine(to: CGPoint(x: center.x + r * cos(a2), y: center.y + r * sin(a2)))
                p.closeSubpath()
                ctx.fill(p, with: .color(.rays))
            }
        }
    }
}

struct AddSheet: View {
    var onAdd: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Вставьте ссылку на подписку (https://…) или ссылки на серверы: vless://, trojan://, vmess://, ss://, hysteria2://.")
                    .font(.subheadline).foregroundColor(.choco)
                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .padding(6)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.line))
                Button {
                    if let s = UIPasteboard.general.string { text = s }
                } label: { Label("Вставить из буфера", systemImage: "doc.on.clipboard") }
                .foregroundColor(.pink)
            }
            .padding()
            .navigationTitle("Добавить")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Отмена") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Добавить") { onAdd(text); dismiss() }
                        .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .onAppear {
            if let s = UIPasteboard.general.string,
               s.components(separatedBy: .whitespacesAndNewlines).contains(where: { LinkParser.isLink($0) || SubscriptionManager.isSubscriptionURL($0) }) {
                text = s
            }
        }
    }
}

struct LogSheet: View {
    @ObservedObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @State private var text = "Загружаю…"

    var body: some View {
        NavigationView {
            ScrollView {
                Text(text).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).padding()
                    .textSelection(.enabled)
            }
            .navigationTitle("Журнал")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Закрыть") { dismiss() } }
                ToolbarItem(placement: .primaryAction) { Button("Копировать") { UIPasteboard.general.string = text } }
            }
        }
        .task { text = await vpn.fetchLog() }
    }
}
