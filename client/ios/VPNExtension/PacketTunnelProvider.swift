import NetworkExtension
import Security

enum WireGuardTunnelError: Error {
    case invalidTunnelConfiguration
}

private struct TunnelKeychainSecrets: Codable {
    let privateKey: String
    let presharedKey: String?
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Unified logger (writes to both system log and file)
    private let log = Log(category: "PacketTunnelProvider")

    private lazy var adapter: Adapter = {
        return Adapter(with: self)
    }()

    override func startTunnel(
        options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void
    ) {
        if let options = options {
            log.debug("Options: \(options)")
        }

        guard let protocolConfig = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = protocolConfig.providerConfiguration
        else {
          log.error("Failed to parse provider configuration")
          completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
          return
        }

#if os(macOS)
        guard let tunnelConfig = try? TunnelConfiguration.from(dictionary: providerConfig)
        else {
            log.error("Failed to parse tunnel configuration")
            completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
            return
        }
#else
        guard var startData = try? TunnelStartData.from(dictionary: providerConfig)
        else {
            log.error("Failed to parse tunnel configuration")
            completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
            return
        }
        if let ref = protocolConfig.passwordReference {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecValuePersistentRef as String: ref,
                kSecReturnData as String: true,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            if status == errSecSuccess,
               let secretData = item as? Data,
               let secrets = try? JSONDecoder().decode(TunnelKeychainSecrets.self, from: secretData) {
                startData.privateKey = secrets.privateKey
                startData.presharedKey = secrets.presharedKey
            } else {
                log.error("Failed to load tunnel secrets from Keychain (status: \(status))")
                completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
                return
            }
        }
        guard !startData.privateKey.isEmpty else {
            log.error("Tunnel configuration missing private key")
            completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
            return
        }
        let tunnelConfig = TunnelConfiguration(fromStartData: startData)
#endif

        let networkSettings = tunnelConfig.asNetworkSettings()
        self.setTunnelNetworkSettings(networkSettings) { [weak self] error in
            guard let self = self else {
                completionHandler(WireGuardTunnelError.invalidTunnelConfiguration)
                return
            }
            if let error = error {
                self.log.error("Failed to set tunnel network settings: \(String(describing: error))")
                completionHandler(error)
                return
            }
            do {
                try self.adapter.start(tunnelConfiguration: tunnelConfig)
                self.log.info("Tunnel started successfully")
                completionHandler(nil)
            } catch {
                self.log.error("Failed to start tunnel: \(error)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        adapter.stop()
        log.info("Tunnel stopped")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // TODO: messageData should contain a valid message.
        if let handler = completionHandler {
            if let stats = adapter.stats() {
                let data = try? JSONEncoder().encode(stats)
                handler(data)
            } else {
                handler(nil)
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        log.info("System going to sleep")
        completionHandler()
    }

    override func wake() {
        log.info("System waking up")
    }
}
