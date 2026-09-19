import Foundation

// Privacy-minimized evidence collector. Encoded evidence never contains full
// executable paths, directories, remote addresses, or command arguments — only
// allowlisted product names, cwd basenames, launchd labels, and counts.

public struct ProcessEvidence: Codable, Equatable, Sendable {
    public var pid: Int32
    public var appName: String
    /// Allowlisted recognized product name, or nil when unrecognized.
    public var recognizedProduct: String?
    /// Where recognition came from: "path", "cwd", "ancestors", "launchd", "unknown".
    public var identitySource: String
    /// Observed ownership evidence (facts, not inference).
    public var ownershipEvidence: [String]
    /// Weak provenance hints that do NOT prove ownership.
    public var provenanceHints: [String]
    public var launchdLabel: String?
    /// "direct" when the PID itself is registered, "ancestor" when a parent is.
    public var launchdOwnership: String?
    public var launchdStatus: String // "checked", "not_checked", "failed"
    public var inboundCount: Int
    public var outboundCount: Int
    public var otherTrafficCount: Int
    /// Recognized local client app names for inbound loopback connections.
    public var recognizedClients: [String]
    public var establishedScanStatus: String // "available", "unavailable", "failed"
    /// Plain-language observed facts for the UI.
    public var facts: [String]
    /// Plain-language evidence gaps / uncertainties for the UI.
    public var gaps: [String]

    public init(pid: Int32, appName: String, recognizedProduct: String? = nil, identitySource: String = "unknown",
                ownershipEvidence: [String] = [], provenanceHints: [String] = [], launchdLabel: String? = nil,
                launchdOwnership: String? = nil, launchdStatus: String = "not_checked", inboundCount: Int = 0,
                outboundCount: Int = 0, otherTrafficCount: Int = 0, recognizedClients: [String] = [],
                establishedScanStatus: String = "unavailable", facts: [String] = [], gaps: [String] = []) {
        self.pid = pid; self.appName = appName; self.recognizedProduct = recognizedProduct; self.identitySource = identitySource
        self.ownershipEvidence = ownershipEvidence; self.provenanceHints = provenanceHints; self.launchdLabel = launchdLabel
        self.launchdOwnership = launchdOwnership; self.launchdStatus = launchdStatus; self.inboundCount = inboundCount
        self.outboundCount = outboundCount; self.otherTrafficCount = otherTrafficCount; self.recognizedClients = recognizedClients
        self.establishedScanStatus = establishedScanStatus; self.facts = facts; self.gaps = gaps
    }
}

public enum EvidenceCollector {
    public struct Socket: Equatable {
        public var fd: String
        public var local: String
        public var remote: String
        public init(fd: String, local: String, remote: String) { self.fd = fd; self.local = local; self.remote = remote }
    }

    // MARK: - Recognition (pure)

    /// Product names allowed to appear in encoded evidence.
    static let knownProducts: Set<String> = ["Hermes", "Epiphany OS", "OmniRoute", "Omi", "Raycast", "Kimi", "CodexBar", "agy", "Google Chrome"]

    /// Exact-component path recognition. Never substring matching.
    public static func recognize(executable: String, directory: String, ancestors: [String]) -> (product: String?, source: String, ownership: [String], hints: [String]) {
        var product: String?; var source = "unknown"; var ownership: [String] = []; var hints: [String] = []
        let exeParts = executable.split(separator: "/").map(String.init)
        let cwdParts = directory.split(separator: "/").map(String.init)

        func containsSequence(_ parts: [String], _ sequence: [String]) -> Bool {
            guard parts.count >= sequence.count else { return false }
            return (0...(parts.count - sequence.count)).contains { Array(parts[$0..<($0 + sequence.count)]) == sequence }
        }
        // Runtime paths are provenance, not proof of which script is running.
        if containsSequence(exeParts, [".hermes", "venv"]) || containsSequence(exeParts, [".hermes", "hermes-agent", ".venv"]) {
            hints.append("Python from the Hermes environment; runtime provenance alone does not establish ownership")
        }
        if containsSequence(cwdParts, [".hermes", "profiles"]) {
            product = "Hermes"; source = "cwd"; ownership.append("Working directory is inside a Hermes profile")
        }
        // Shared Hermes Node runtime: provenance only, never ownership.
        if containsSequence(exeParts, [".hermes", "node", "bin", "node"]) {
            hints.append("Shared Hermes Node.js runtime; the binary path does not prove which tool owns this listener")
        }
        // OmniRoute package install: exact node_modules component.
        if containsSequence(cwdParts, ["node_modules", "omniroute"]) {
            if product == nil { product = "OmniRoute"; source = "cwd" }
            ownership.append("Working directory is inside the OmniRoute package")
        }
        // Epiphany OS app source layout: exact apps/epiphany-os components.
        if containsSequence(exeParts, ["apps", "epiphany-os"]) || containsSequence(cwdParts, ["apps", "epiphany-os"]) {
            if product == nil { product = "Epiphany OS"; source = containsSequence(exeParts, ["apps", "epiphany-os"]) ? "path" : "cwd" }
            ownership.append("Located inside the Epiphany OS app tree")
        }
        // Desktop bundles: exact component ending ".app" or the canonical ".app.bundle".
        for part in exeParts where part.hasSuffix(".app") || part.hasSuffix(".app.bundle") {
            let bundleName = part.hasSuffix(".app.bundle") ? String(part.dropLast(".app.bundle".count)) : String(part.dropLast(".app".count))
            if knownProducts.contains(bundleName) {
                if product == nil { product = bundleName; source = "path" }
                ownership.append("Located inside the \(bundleName) desktop bundle")
            }
        }
        // Ancestor process names: exact match only.
        for ancestor in ancestors {
            let trimmed = ancestor.hasSuffix(".app") ? String(ancestor.dropLast(4)) : ancestor
            if knownProducts.contains(trimmed) {
                if product == nil { product = trimmed; source = "ancestors"; ownership.append("Launched by \(trimmed)") }
                else if trimmed != product { hints.append("Ancestor process named \(trimmed) is present") }
            } else if ancestor.hasSuffix(".app") || ancestor.hasSuffix(".app.bundle") {
                hints.append("Runs under a desktop app bundle ancestor")
            }
        }
        return (product, source, ownership, hints)
    }

    // MARK: - launchd (pure parsing + derivation)

    public static func parseLaunchctl(_ text: String) -> [Int32: String] {
        var table: [Int32: String] = [:]
        for line in text.split(separator: "\n") {
            let columns = line.split(separator: "\t", omittingEmptySubsequences: true).map(String.init)
            guard columns.count >= 3, let pid = Int32(columns[0]), pid > 0 else { continue }
            table[pid] = columns[2]
        }
        return table
    }

    /// Drop noisy Apple application-instance suffixes (trailing numeric/hex segments).
    public static func normalizeLabel(_ label: String) -> String {
        guard label.hasPrefix("application.") else { return label }
        return label.replacingOccurrences(of: #"\.[0-9]+\.[0-9]+(?:\.[A-Fa-f0-9-]{36})?$"#, with: "", options: .regularExpression)
    }

    public static func launchdLabel(pidChain: [Int32], table: [Int32: String]) -> (label: String?, direct: Bool) {
        for pid in pidChain {
            if let label = table[pid] { return (normalizeLabel(label), pid == pidChain.first) }
        }
        return (nil, false)
    }

    // MARK: - Established sockets (pure parsing + classification)

    public static func normalizeEndpoint(_ endpoint: String) -> String {
        var value = endpoint
        if value.hasPrefix("[") { // [::1]:1234
            if let close = value.firstIndex(of: "]") {
                var host = String(value[value.index(after: value.startIndex)..<close])
                if host.hasPrefix("::ffff:"), host.contains(".") { host = String(host.dropFirst(7)) }
                let port = close < value.endIndex && value.index(after: close) < value.endIndex ? String(value[value.index(after: close)...]).drop(while: { $0 == ":" }) : ""
                return "\(host == "localhost" ? "::1" : host):\(port)"
            }
        }
        if value.hasPrefix("localhost:") { value = value.replacingOccurrences(of: "localhost:", with: "127.0.0.1:") }
        return value
    }

    public static func isLoopback(_ endpoint: String) -> Bool {
        let normalized = normalizeEndpoint(endpoint)
        return normalized.hasPrefix("127.0.0.1:") || normalized.hasPrefix("::1:")
    }

    public static func port(of endpoint: String) -> String? {
        normalizeEndpoint(endpoint).split(separator: ":", omittingEmptySubsequences: false).last.map(String.init)
    }

    /// Parses `lsof -nP -iTCP -sTCP:ESTABLISHED -Fpcfn` raw text.
    public static func parseEstablished(_ text: String) -> [Int32: [Socket]] {
        var result: [Int32: [Socket]] = [:]; var pid: Int32?; var fd: String?
        for line in text.split(separator: "\n") {
            guard let field = line.first else { continue }
            let value = String(line.dropFirst())
            switch field {
            case "p": pid = Int32(value); fd = nil
            case "c": _ = value // command name; not encoded in evidence
            case "f": fd = value
            case "n":
                guard let pid, let currentFd = fd else { continue }
                fd = nil
                let sides = value.split(separator: "->", maxSplits: 1).map(String.init)
                guard sides.count == 2 else { continue }
                result[pid, default: []].append(Socket(fd: currentFd, local: normalizeEndpoint(sides[0]), remote: normalizeEndpoint(sides[1])))
            default: break
            }
        }
        return result
    }

    /// Classify a listener's established sockets. Inbound = socket whose local
    /// address and port match a listening endpoint (counted by FD).
    /// Loopback clients are matched against other PIDs' reverse sockets.
    public static func classify(sockets: [Socket], listenEndpoints: Set<String>, allSockets: [Int32: [Socket]]) -> (inbound: Int, outbound: Int, other: Int, clientPids: [Int32]) {
        var inbound = 0; var outbound = 0; var other = 0; var clients: Set<Int32> = []
        let endpoints = Set(listenEndpoints.map(normalizeEndpoint))
        for socket in sockets {
            let localPort = port(of: socket.local) ?? ""
            if endpoints.contains(normalizeEndpoint(socket.local)) || endpoints.contains("*:\(localPort)") || endpoints.contains("0.0.0.0:\(localPort)") || endpoints.contains(":::\(localPort)") {
                inbound += 1
                if isLoopback(socket.remote) {
                    for (otherPid, otherSockets) in allSockets {
                        guard otherSockets.contains(where: { $0.remote == socket.local && $0.local == socket.remote }) else { continue }
                        clients.insert(otherPid); break
                    }
                }
            } else if isLoopback(socket.local) && isLoopback(socket.remote) {
                outbound += 1
            } else {
                other += 1
            }
        }
        return (inbound, outbound, other, clients.sorted())
    }

    // MARK: - Collection

    public static func collect(rows: [Listener], establishedText: String, connectionScanAvailable: Bool = true,
                               launchctlText: String? = nil) -> [Int32: ProcessEvidence] {
        let launchctlTable: [Int32: String]
        var launchdStatus = "not_checked"
        if let launchctlText {
            launchctlTable = parseLaunchctl(launchctlText); launchdStatus = "checked"
        } else if let text = readLaunchctl() {
            launchctlTable = parseLaunchctl(text); launchdStatus = "checked"
        } else {
            launchctlTable = [:]; launchdStatus = "failed"
        }
        let established = connectionScanAvailable ? parseEstablished(establishedText) : [:]
        var result: [Int32: ProcessEvidence] = [:]
        for row in rows {
            result[row.pid] = evidence(for: row, established: established, connectionScanAvailable: connectionScanAvailable, launchctlTable: launchctlTable, launchdStatus: launchdStatus)
        }
        return result
    }

    static func evidence(for row: Listener, established: [Int32: [Socket]], connectionScanAvailable: Bool,
                         launchctlTable: [Int32: String], launchdStatus: String) -> ProcessEvidence {
        var facts: [String] = []; var gaps: [String] = []
        let recognized = recognize(executable: row.executable, directory: row.directory, ancestors: row.ancestors)
        var ownership = recognized.ownership
        var hints = recognized.hints

        // launchd: traverse parent chain (bounded 12) and match exact PIDs.
        var chain: [Int32] = [row.pid]; var next = row.parent; var seen: Set<Int32> = [row.pid]
        while next > 1 && chain.count < 12 && !seen.contains(next) {
            seen.insert(next); chain.append(next)
            guard let ancestor = Scanner.identity(next) else { break }
            next = ancestor.parent
        }
        let (label, direct) = launchdLabel(pidChain: chain, table: launchctlTable)
        if let label {
            facts.append(direct ? "Registered with launchd directly as \"\(label)\"" : "Managed through an ancestor launchd service \"\(label)\"")
            if label.hasPrefix("com.epiphany.") { ownership.append("Registered as an Epiphany launchd service") }
            gaps.append("A launchd registration alone does not prove the service is still needed or has KeepAlive configured")
        } else if launchdStatus == "checked" {
            facts.append("Not registered with launchd under this PID or its ancestors")
        } else if launchdStatus == "failed" {
            gaps.append("launchd status could not be read, so a managed-service role cannot be ruled out")
        }

        // Established connections.
        var scanStatus = "available"
        var inbound = 0; var outbound = 0; var other = 0; var clientNames: [String] = []
        if !connectionScanAvailable {
            scanStatus = "unavailable"
            gaps.append("Established-connection scan was unavailable, so current-use evidence is missing (this is not zero usage)")
        } else {
            let sockets = established[row.pid] ?? []
            let classification = classify(sockets: sockets, listenEndpoints: Set(row.endpoints), allSockets: established)
            inbound = classification.inbound; outbound = classification.outbound; other = classification.other
            clientNames = classification.clientPids.map { clientPid in
                Scanner.identity(clientPid)?.appName ?? "PID \(clientPid)"
            }
            if inbound > 0 {
                facts.append(inbound == 1 ? "1 accepted connection on its listening port" : "\(inbound) accepted connections on its listening ports")
                if !clientNames.isEmpty { facts.append("Connected locally by \(clientNames.joined(separator: ", "))") }
            } else {
                gaps.append("No accepted connections were observed at scan time; that is not proof the listener is unused")
            }
            if other > 0 { gaps.append("\(other) other network connection\(other == 1 ? "" : "s") (not on its listening ports) were open; this traffic does not prove the listener is used") }
            if outbound > 0 { facts.append("\(outbound) outgoing local connection\(outbound == 1 ? "" : "s") to other services") }
        }

        // Role hints from observable metadata only.
        if row.name == "ssh" && !row.endpoints.isEmpty {
            hints.append("SSH process listening locally; commonly a port-forward tunnel rather than a server")
        }

        let listenSummary = row.ports.joined(separator: ", ")
        if !listenSummary.isEmpty { facts.append("Listening on port\(row.ports.count == 1 ? "" : "s") \(listenSummary)") }

        var evidence = ProcessEvidence(
            pid: row.pid, appName: row.appName, recognizedProduct: recognized.product, identitySource: recognized.source,
            ownershipEvidence: ownership, provenanceHints: hints, launchdLabel: label,
            launchdOwnership: label != nil ? (direct ? "direct" : "ancestor") : nil, launchdStatus: launchdStatus,
            inboundCount: inbound, outboundCount: outbound, otherTrafficCount: other, recognizedClients: clientNames,
            establishedScanStatus: scanStatus, facts: facts, gaps: gaps)
        evidence.facts.append(contentsOf: ownership.map { "Ownership evidence: \($0)" })
        evidence.gaps.append(contentsOf: hints.map { "Unverified hint: \($0)" })
        if recognized.product == nil && recognized.source == "unknown" {
            evidence.gaps.append("No recognized product identity; purpose must be judged from context alone")
        }
        return evidence
    }

    static func readLaunchctl() -> String? {
        let task = Process(); let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl"); task.arguments = ["list"]
        task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { return nil }
        let timeout = DispatchWorkItem { if task.isRunning { task.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit(); timeout.cancel()
        guard task.terminationReason == .exit && task.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}
