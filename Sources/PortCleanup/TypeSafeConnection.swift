import SwiftUI
import Security
import LocalAuthentication
import PortCore

/// Uses the same item as PortCore.Credential; keys never enter preferences or files.
struct TypeSafeKeyStore {
    var service = "ai.epiphany.port-cleanup.typesafe"
    var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service, kSecAttrAccount as String: "typesafe"]
    }
    static func normalized(_ input: String) throws -> String {
        let key = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty, !key.unicodeScalars.contains(where: {
            CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0)
        }) else { throw PortError("Paste only your TypeSafe API key, without spaces or extra lines.") }
        return key
    }
    func read() throws -> String {
        var request = query
        let context = LAContext(); context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let key = String(data: data, encoding: .utf8), !key.isEmpty else {
            throw PortError("No readable TypeSafe key. Save your key again to reconnect. Local scan and cleanup still work.")
        }
        return key
    }
    var isSaved: Bool { (try? read()) != nil }
    func save(_ input: String) throws {
        let key = try Self.normalized(input)
        var item = query
        item[kSecValueData as String] = Data(key.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(item as CFDictionary, nil)
        let status = added == errSecDuplicateItem
            ? SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data(key.utf8)] as CFDictionary)
            : added
        guard status == errSecSuccess else {
            throw PortError("Could not save to Keychain (\(status)). If macOS asks, allow Port Cleanup access, then try again.")
        }
        guard try read() == key else { throw PortError("Keychain read-back failed. Save the key again before using Jev.") }
    }
}

struct TypeSafeConnectionView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared
    @ViewState private var key = ""
    @ViewState private var failure: String?
    @ViewState private var saved = TypeSafeKeyStore().isSaved
    let onSave: () -> Void

    var body: some View {
        ZStack {
            MissionControlBackdrop()

            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill((saved ? MissionTheme.emerald : MissionTheme.amber).opacity(0.18))
                            .frame(width: 46, height: 46)
                        Image(systemName: saved ? "checkmark.key.fill" : "key.fill")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundStyle(saved ? MissionTheme.emerald : MissionTheme.amber)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Connect TypeSafe for Jev")
                            .font(.system(size: 21, weight: .bold, design: .rounded))
                        Text("Add your API key once for Jev triage. Local scanning, inspection, and cleanup always work without a key.")
                            .font(.system(size: 12.5))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                HStack(spacing: 10) {
                    VerdictBadge(
                        label: saved ? "API key saved in macOS Keychain" : "No readable API key in Keychain",
                        icon: saved ? "checkmark.shield.fill" : "key.fill",
                        tint: saved ? MissionTheme.emerald : MissionTheme.amber
                    )
                    Spacer()
                    Link(destination: URL(string: "https://typesafe.ai")!) {
                        HStack(spacing: 4) {
                            Text("Get a TypeSafe API key")
                            Image(systemName: "arrow.up.right")
                        }
                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                        .foregroundStyle(MissionTheme.teal)
                    }
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.cardFill(colorScheme, elevated: true)))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))

                VStack(alignment: .leading, spacing: 8) {
                    Text(saved ? "REPLACE SAVED KEY" : "ENTER TYPESAFE API KEY")
                        .font(.system(size: 10, weight: .heavy, design: .monospaced))
                        .foregroundStyle(.secondary)

                    SecureField(saved ? "Paste a replacement API key" : "Paste your TypeSafe API key", text: $key)
                        .textFieldStyle(.roundedBorder)
                        .colorScheme(.light)
                        .accessibilityIdentifier("typesafe-api-key")
                        .onSubmit { save() }
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(MissionTheme.cardFill(colorScheme)))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))

                VStack(alignment: .leading, spacing: 8) {
                    Label("Keychain Vault & Explicit Request Guarantee", systemImage: "lock.shield")
                        .font(.system(size: 12.5, weight: .bold, design: .rounded))
                        .foregroundStyle(MissionTheme.teal)
                    Text("Stored exclusively in this Mac's Keychain (`ai.epiphany.port-cleanup.typesafe`)—never in preferences, files, or repositories. Saving checks local storage only; TypeSafe validates the key on your next Jev request.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    Text("Each 'Scan all with Jev' or single-process interpretation click makes one explicit request with minimized process evidence. Saving a key never starts a scan automatically.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(MissionTheme.subtleWell(colorScheme)))

                if let failure {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(MissionTheme.amber)
                        Text(failure)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(MissionTheme.amber)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(MissionTheme.amber.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }

                HStack {
                    Button("Cancel") { key = ""; dismiss() }
                        .keyboardShortcut(.cancelAction)
                        .buttonStyle(ChromeButtonStyle())
                    Spacer()
                    Button(saved ? "Replace saved key" : "Save API key") { save() }
                        .disabled((try? TypeSafeKeyStore.normalized(key)) == nil)
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                        .accessibilityIdentifier("typesafe-save")
                }
            }
            .padding(24)
        }
        .frame(width: 560)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
        .onDisappear { key = "" }
    }

    private func save() {
        do {
            try TypeSafeKeyStore().save(key)
            key = ""; failure = nil; saved = true
            onSave(); dismiss()
        } catch { failure = error.localizedDescription }
    }
}
