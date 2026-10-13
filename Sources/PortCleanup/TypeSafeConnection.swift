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
    @ViewState private var key = ""
    @ViewState private var failure: String?
    @ViewState private var saved = TypeSafeKeyStore().isSaved
    let onSave: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Connect TypeSafe", systemImage: "key.fill").font(.title2.bold())
            Text("Add your API key once to use Jev recommendations. Local scanning, inspection, and cleanup work without a key.")
            Link("Get a TypeSafe API key ↗", destination: URL(string: "https://typesafe.ai")!)
            Label(saved ? "API key saved in Keychain" : "No readable API key saved", systemImage: saved ? "checkmark.shield.fill" : "key")
                .foregroundStyle(saved ? Color.green : Color.secondary)
            SecureField(saved ? "Paste a replacement API key" : "Paste your TypeSafe API key", text: $key)
                .textFieldStyle(.roundedBorder)
                .colorScheme(.light)
                .accessibilityIdentifier("typesafe-api-key")
                .onSubmit { save() }
            Text("Stored only in this Mac’s Keychain, not in the app, settings, or repository. Saving checks local storage only; TypeSafe accepts or rejects the key on your next Jev request.")
                .font(.callout).foregroundStyle(.secondary)
            Text("Jev sends minimized process evidence to TypeSafe. Each Scan all with Jev or interpretation click makes one paid request. Saving a key does not start a scan.")
                .font(.callout).foregroundStyle(.secondary)
            if let failure { Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
            HStack {
                Button("Cancel") { key = ""; dismiss() }.keyboardShortcut(.cancelAction).buttonStyle(ChromeButtonStyle())
                Spacer()
                Button(saved ? "Replace saved key" : "Save API key") { save() }
                    .disabled((try? TypeSafeKeyStore.normalized(key)) == nil)
                    .keyboardShortcut(.defaultAction).buttonStyle(ChromeButtonStyle())
                    .accessibilityIdentifier("typesafe-save")
            }
        }.padding(24).frame(width: 530)
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
