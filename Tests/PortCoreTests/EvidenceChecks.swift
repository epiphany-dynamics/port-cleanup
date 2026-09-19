import Foundation
import PortCore

// Evidence collector checks. Pure fixture-driven checks only; no processes are
// killed, no network calls, no paid APIs. Entry point: runEvidenceChecks().

func evidenceCheck(_ condition: Bool, _ label: String) throws {
    guard condition else { throw CheckError.failed(label) }
}

enum CheckError: Error { case failed(String) }

// MARK: - Listener fixture helper

func makeListener(pid: Int32, name: String, executable: String, directory: String,
                  parent: Int32 = 1, endpoints: [String], ancestors: [String] = []) -> Listener {
    Listener(pid: pid, name: name, executable: executable, directory: directory, uid: 501,
             start: 0, parent: parent, ancestors: ancestors, endpoints: endpoints)
}

// MARK: - Checks

func checkEstablishedIPv4AndIPv6Parsing() throws {
    let text = """
    p100
    cnode
    f15
    n127.0.0.1:4520->127.0.0.1:51000
    f16
    n[::1]:4520->[::1]:51001
    p200
    cpython
    f19
    n192.168.1.5:443->10.0.0.2:52000
    """
    let parsed = EvidenceCollector.parseEstablished(text)
    try evidenceCheck(parsed[100]?.count == 2, "IPv4+IPv6: two sockets for pid 100")
    try evidenceCheck(parsed[100]?[0] == EvidenceCollector.Socket(fd: "15", local: "127.0.0.1:4520", remote: "127.0.0.1:51000"), "IPv4 socket fields")
    try evidenceCheck(parsed[100]?[1].local == "::1:4520", "IPv6 normalized to ::1")
    try evidenceCheck(parsed[100]?[1].remote == "::1:51001", "IPv6 remote normalized")
    try evidenceCheck(parsed[200]?[0].local == "192.168.1.5:443", "non-loopback IPv4 kept")
    try evidenceCheck(EvidenceCollector.isLoopback("localhost:8080"), "localhost treated as loopback")
    try evidenceCheck(!EvidenceCollector.isLoopback("10.0.0.2:52000"), "remote IP is not loopback")
}

func checkIncomingVsOutgoingClassification() throws {
    // Listener pid 100 on 127.0.0.1:9223. Client pid 200 connects to it (reverse
    // socket). Listener pid 100 also makes its own outgoing local connection.
    let established = EvidenceCollector.parseEstablished("""
    p100
    cnode
    f10
    n127.0.0.1:9223->127.0.0.1:51000
    f11
    n127.0.0.1:51001->127.0.0.1:5432
    p200
    cchrome
    f20
    n127.0.0.1:51000->127.0.0.1:9223
    """)
    let sockets = try XCTUnwrap(established[100] ?? [])
    let classification = EvidenceCollector.classify(sockets: sockets, listenEndpoints: ["127.0.0.1:9223"], allSockets: established)
    try evidenceCheck(classification.inbound == 1, "one accepted inbound connection")
    try evidenceCheck(classification.outbound == 1, "one outgoing local connection")
    try evidenceCheck(classification.other == 0, "no other traffic")
    try evidenceCheck(classification.clientPids == [200], "reverse local client pid identified")
}

func checkUnknownReadStatusNotZero() throws {
    let row = makeListener(pid: 300, name: "node", executable: "/usr/local/bin/node",
                           directory: "/tmp/project", endpoints: ["127.0.0.1:3000"])
    // Scan unavailable: evidence must expose a gap, not imply zero usage.
    let unavailable = EvidenceCollector.collect(rows: [row], establishedText: "", connectionScanAvailable: false, launchctlText: "")
    try evidenceCheck(unavailable[300]?.establishedScanStatus == "unavailable", "status marked unavailable")
    try evidenceCheck(unavailable[300]?.inboundCount == 0, "counts remain zero when unknown")
    try evidenceCheck(unavailable[300]?.gaps.contains { $0.contains("not proof the listener is unused") || $0.contains("not zero usage") } == true, "gap explains metadata missing is not zero")
    // A successful scan with no records means none observed, not a failed scan.
    let missing = EvidenceCollector.collect(rows: [row], establishedText: "", connectionScanAvailable: true, launchctlText: "")
    try evidenceCheck(missing[300]?.establishedScanStatus == "available", "successful empty scan remains available")
    try evidenceCheck(missing[300]?.gaps.contains { $0.contains("not proof") } == true, "empty observation is not proof of abandonment")
}

func checkFalseSubstringNotMatched() throws {
    // Look-alike components must not trigger recognition.
    let fakeVenv = makeListener(pid: 400, name: "python", executable: "/tmp/.hermes-fake/bin/python",
                                directory: "/tmp/hermesish-project", endpoints: ["127.0.0.1:8000"])
    let (product, _, ownership, hints) = EvidenceCollector.recognize(executable: fakeVenv.executable, directory: fakeVenv.directory, ancestors: [])
    try evidenceCheck(product == nil, "look-alike paths are not recognized")
    try evidenceCheck(ownership.isEmpty, "no ownership evidence from false substrings")
    try evidenceCheck(hints.isEmpty, "no hints from false substrings")
    // OmniRoute substring inside a different package name must not match.
    let decoy = EvidenceCollector.recognize(executable: "/usr/bin/node", directory: "/tmp/.local/lib/node_modules/omniroute-spoof/dist", ancestors: [])
    try evidenceCheck(decoy.product == nil, "package-name substring is not matched")
}

func checkSharedHermesNodeRuntimeIsHintOnly() throws {
    let shared = makeListener(pid: 500, name: "node", executable: "/Users/u/.hermes/node/bin/node",
                              directory: "/Users/u/work", endpoints: ["127.0.0.1:4545"])
    let (product, _, ownership, hints) = EvidenceCollector.recognize(executable: shared.executable, directory: shared.directory, ancestors: [])
    try evidenceCheck(product == nil, "shared node runtime is not conclusive ownership")
    try evidenceCheck(ownership.isEmpty, "no ownership claim for shared runtime")
    try evidenceCheck(hints.contains { $0.contains("Shared Hermes Node.js runtime") }, "shared runtime surfaced as a hint")
}

func checkKnownNodeModulesPackageRecognized() throws {
    let omni = makeListener(pid: 600, name: "node", executable: "/Users/u/.hermes/node/bin/node",
                            directory: "/Users/u/.local/lib/node_modules/omniroute/dist", endpoints: ["127.0.0.1:8787"])
    let (product, source, ownership, _) = EvidenceCollector.recognize(executable: omni.executable, directory: omni.directory, ancestors: [])
    try evidenceCheck(product == "OmniRoute", "OmniRoute recognized from cwd node_modules component")
    try evidenceCheck(source == "cwd", "identity source is cwd")
    try evidenceCheck(ownership.contains { $0.contains("OmniRoute") }, "ownership evidence recorded")
    // Hermes venv python with Hermes ancestor also recognized as Hermes runtime.
    let hermes = makeListener(pid: 601, name: "python", executable: "/Users/u/.hermes/venv/bin/python",
                              directory: "/Users/u/.hermes/profiles/business-hormozi-advisor", endpoints: ["127.0.0.1:4747"])
    let hermesResult = EvidenceCollector.recognize(executable: hermes.executable, directory: hermes.directory, ancestors: ["Hermes"])
    try evidenceCheck(hermesResult.product == "Hermes", "Hermes venv path recognized")
    try evidenceCheck(hermesResult.ownership.contains { $0.contains("Hermes profile") }, "profile context recorded independently of runtime")
    // Canonical desktop bundle components (both .app and .app.bundle).
    let chrome = EvidenceCollector.recognize(executable: "/Applications/Google Chrome.app.bundle/Contents/MacOS/Google Chrome", directory: "/tmp", ancestors: [])
    try evidenceCheck(chrome.product == "Google Chrome", "canonical .app.bundle path recognized via exact component")
}

func checkLaunchdDirectAndAncestor() throws {
    let table = EvidenceCollector.parseLaunchctl("\t-\t0\tcom.apple.opendirectoryd\n79857\t0\tcom.epiphany.linear-dispatch-bridge\n500\t1\tapplication.com.apple.Safari.12345678.ABCDEF12\n")
    try evidenceCheck(table[79857] == "com.epiphany.linear-dispatch-bridge", "exact pid to label mapping")
    // Direct.
    let direct = EvidenceCollector.launchdLabel(pidChain: [79857, 1], table: table)
    try evidenceCheck(direct.label == "com.epiphany.linear-dispatch-bridge", "direct label found")
    try evidenceCheck(direct.direct, "direct ownership flagged")
    // Ancestor-managed: chain pid 9287 -> parent 9285 -> label on 9285.
    let ancestorTable = EvidenceCollector.parseLaunchctl("9285\t0\tcom.epiphany.some-bridge\n")
    let ancestor = EvidenceCollector.launchdLabel(pidChain: [9287, 9285, 1], table: ancestorTable)
    try evidenceCheck(ancestor.label == "com.epiphany.some-bridge", "ancestor label found")
    try evidenceCheck(!ancestor.direct, "ancestor-managed distinguished from direct")
    // Apple application instance suffix trimmed.
    try evidenceCheck(EvidenceCollector.normalizeLabel("application.com.raycast.macos.20966683.177292806.F5A8E591-36F3-4576-A241-AEC2EC80D63B") == "application.com.raycast.macos", "observed Apple instance suffix omitted")
    try evidenceCheck(EvidenceCollector.normalizeLabel("com.example.service.12345678") == "com.example.service.12345678", "non-application service label preserved")
    // No registration.
    let none = EvidenceCollector.launchdLabel(pidChain: [9999, 1], table: table)
    try evidenceCheck(none.label == nil, "unregistered pid has no label")
}

func checkLaunchdOwnershipInEvidence() throws {
    let row = makeListener(pid: 79857, name: "Python", executable: "/usr/bin/python3",
                           directory: "/Users/u/epiphany/scripts/linear-dispatch", parent: 1, endpoints: ["127.0.0.1:5757"])
    let collected = EvidenceCollector.collect(rows: [row], establishedText: "", connectionScanAvailable: true,
                                              launchctlText: "79857\t0\tcom.epiphany.linear-dispatch-bridge\n")
    let evidence = try XCTUnwrap(collected[79857])
    try evidenceCheck(evidence.launchdLabel == "com.epiphany.linear-dispatch-bridge", "label surfaced in evidence")
    try evidenceCheck(evidence.launchdOwnership == "direct", "direct launchd ownership flagged")
    try evidenceCheck(evidence.ownershipEvidence.contains { $0.contains("Epiphany launchd service") }, "launchd role recorded as ownership evidence")
    try evidenceCheck(evidence.gaps.contains { $0.contains("does not prove") }, "launchd registration treated as not proof of need")
}

func checkCollectFullEvidence() throws {
    let hermes = makeListener(pid: 1582, name: "python", executable: "/Users/u/.hermes/venv/bin/python",
                              directory: "/Users/u/.hermes/profiles/business-hormozi-advisor", parent: 9285,
                              endpoints: ["127.0.0.1:4747"], ancestors: ["Hermes"])
    let collected = EvidenceCollector.collect(rows: [hermes], establishedText: "p1582\nf8\nn127.0.0.1:4747->127.0.0.1:51000\n", connectionScanAvailable: true, launchctlText: "9285\t0\tcom.epiphany.hermes-bridge\n")
    let evidence = try XCTUnwrap(collected[1582])
    try evidenceCheck(evidence.recognizedProduct == "Hermes", "Hermes identity recognized")
    try evidenceCheck(evidence.facts.count >= 2, "plain-language facts exposed")
    try evidenceCheck(evidence.gaps.isEmpty == false, "uncertainties exposed even with positive evidence")
    try evidenceCheck(evidence.launchdOwnership == "ancestor", "ancestor-managed launchd service detected")
    try evidenceCheck(evidence.inboundCount == 1, "inbound counted by fd")
}

func checkNoSensitiveDataEncoded() throws {
    let row = makeListener(pid: 700, name: "node", executable: "/Users/u/secret-dir/.hermes/node/bin/node",
                           directory: "/Users/u/secret-dir/project", endpoints: ["127.0.0.1:9000"], ancestors: ["Hermes"])
    let collected = EvidenceCollector.collect(rows: [row], establishedText: "p700\nf8\nn127.0.0.1:9000->127.0.0.1:51000\n", connectionScanAvailable: true, launchctlText: "")
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    let json = String(decoding: (try encoder.encode(try XCTUnwrap(collected[700]))), as: UTF8.self)
    try evidenceCheck(!json.contains("secret-dir"), "no full paths in encoded evidence")
    try evidenceCheck(!json.contains("51000"), "no remote ephemeral port in encoded evidence")
    try evidenceCheck(!json.contains("/Users/u"), "no absolute path fragments in encoded evidence")
}

func checkRuntimeProvenanceDoesNotBecomeOwnership() throws {
    let r = EvidenceCollector.recognize(executable: "/Users/u/.hermes/hermes-agent/.venv/bin/python", directory: "/tmp/unrelated", ancestors: [])
    try evidenceCheck(r.product == nil && r.ownership.isEmpty && !r.hints.isEmpty, "venv only is provenance")
    let unrelated = EvidenceCollector.recognize(executable: "/usr/bin/node", directory: "/tmp/node_modules/other/omniroute", ancestors: [])
    try evidenceCheck(unrelated.product == nil, "nonadjacent package names do not imply ownership")
}

func checkAddressMustMatchListener() throws {
    let parsed = EvidenceCollector.parseEstablished("p100\nf8\nn192.168.1.20:9000->192.168.1.25:55555\nf9\nn[::ffff:127.0.0.1]:9000->127.0.0.1:50000\n")
    let result = EvidenceCollector.classify(sockets: parsed[100] ?? [], listenEndpoints: ["127.0.0.1:9000"], allSockets: parsed)
    try evidenceCheck(result.inbound == 1 && result.other == 1, "same port on a different interface is not accepted usage; mapped loopback matches")
}

func checkEvidenceReachesJevWithoutPaths() throws {
    var row = makeListener(pid: 333, name: "node", executable: "/Users/u/private/.hermes/node/bin/node", directory: "/Users/u/private/node_modules/omniroute/dist", endpoints: ["127.0.0.1:2000"])
    row.evidence = EvidenceCollector.collect(rows: [row], establishedText: "", launchctlText: "333\t0\tcom.epiphany.test\n")[333]
    let data = try Jev.payload(rows: [row], rules: "Keep daily tools")
    let text = String(decoding: data, as: UTF8.self)
    try evidenceCheck(text.contains("OmniRoute") && text.contains("com.epiphany.test") && text.contains("inboundCount"), "richer evidence arrives in model state")
    try evidenceCheck(!text.contains("/Users/") && !text.contains("private"), "no raw paths reach model state")
}

// MARK: - Entry point

func runEvidenceChecks() throws -> Int {
    var passed = 0
    let checks: [(String, () throws -> Void)] = [
        ("established IPv4+IPv6 parsing", checkEstablishedIPv4AndIPv6Parsing),
        ("incoming vs outgoing classification", checkIncomingVsOutgoingClassification),
        ("unknown read status is not zero", checkUnknownReadStatusNotZero),
        ("false substrings not matched", checkFalseSubstringNotMatched),
        ("shared Hermes node runtime is hint only", checkSharedHermesNodeRuntimeIsHintOnly),
        ("known node_modules package recognized", checkKnownNodeModulesPackageRecognized),
        ("launchd direct and ancestor logic", checkLaunchdDirectAndAncestor),
        ("launchd ownership in evidence", checkLaunchdOwnershipInEvidence),
        ("collect full evidence", checkCollectFullEvidence),
        ("no sensitive data encoded", checkNoSensitiveDataEncoded),
        ("runtime provenance is not ownership", checkRuntimeProvenanceDoesNotBecomeOwnership),
        ("listener address must match", checkAddressMustMatchListener),
        ("evidence reaches Jev without paths", checkEvidenceReachesJevWithoutPaths),
    ]
    for (name, check) in checks {
        try check(); passed += 1
        print("ok - \(name)")
    }
    return passed
}

// MARK: - Test helper (XCTest-free)

func XCTUnwrap<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T {
    guard let value else { throw CheckError.failed("unexpected nil at \(file):\(line)") }
    return value
}
