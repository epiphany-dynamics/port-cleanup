import Foundation
import Security
import PortCore

/// Read-only with respect to processes; uses only its own disposable Keychain item.
enum TypeSafeConnectionChecks {
    static func run() throws {
        let store = TypeSafeKeyStore(service: "ai.epiphany.port-cleanup.test.\(UUID().uuidString)")
        defer { SecItemDelete(store.query as CFDictionary) }
        precondition(!store.isSaved)
        for invalid in ["", " \n ", "one two", "one\ntwo", "one\0two"] {
            do { _ = try TypeSafeKeyStore.normalized(invalid); throw PortError("Invalid key accepted") }
            catch let error as PortError { precondition(error.message != "Invalid key accepted") }
        }
        let first = "test-only-\(UUID().uuidString)"
        try store.save(" \(first)\n")
        precondition(store.isSaved)
        let savedFirst = try store.read(); precondition(savedFirst == first)
        let second = "replacement-test-only-\(UUID().uuidString)"
        try store.save(second)
        let savedSecond = try store.read(); precondition(savedSecond == second)
        do { try store.save("bad key"); throw PortError("Invalid replacement accepted") }
        catch let error as PortError { precondition(error.message != "Invalid replacement accepted") }
        let preserved = try store.read(); precondition(preserved == second)
        print("TypeSafe setup checks passed: missing key, input validation, save/read-back, explicit replacement, invalid replacement preserves saved key. No API requests or process signals.")
    }
}
