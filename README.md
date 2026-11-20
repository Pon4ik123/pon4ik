# Pon4ik

VPN-клиент с пончиком: Windows, macOS и iOS. Ядро — [Xray-core](https://github.com/XTLS/Xray-core).

## iOS

- `ios/App` — приложение (SwiftUI), `ios/PacketTunnel` — VPN-расширение, `ios/Shared` — подписки, ссылки, конфиг.
- `ios/Core` — обёртка над Xray-core, собирается `gomobile` в `Pon4ikCore.xcframework`.
- Сборка — GitHub Actions (`.github/workflows/ios.yml`) на macOS-машине GitHub.
