import Foundation
import PortCore
func XCTAssertEqual<T: Equatable>(_ a: T, _ b: T) { precondition(a == b, "Expected \(a) == \(b)") }
func XCTAssertNotEqual<T: Equatable>(_ a: T, _ b: T) { precondition(a != b) }
func XCTAssertNotNil<T>(_ a: T?) { precondition(a != nil) }
func XCTAssertNil<T>(_ a: T?) { precondition(a == nil) }
func XCTAssertTrue(_ a: Bool) { precondition(a) }
func XCTAssertFalse(_ a: Bool) { precondition(!a) }

final class CoreTests {
    func row(pid: Int32 = 43210, start: UInt64 = 11, ports: [String] = ["127.0.0.1:4520"]) -> Listener {
        Listener(pid: pid, name: "node", executable: "/opt/homebrew/bin/node", directory: "/tmp/project", uid: getuid(), start: start, parent: 1, ancestors: [], endpoints: ports)
    }
    func testParserGroupsAllSocketsWithoutDuplicates() {
        let parsed = Scanner.parse("p43210\ncnode\nu501\nf12\nn127.0.0.1:4520\nf13\nn*:4521\np43210\nf14\nn127.0.0.1:4520\n")
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed[43210]?.endpoints.sorted(), ["*:4521", "127.0.0.1:4520"])
    }
    func testPIDReuseIsNeverAllowed() {
        XCTAssertNotNil(Stopper.refusal(expected: row(), current: row(start: 12), protected: false))
    }
    func testChangedPortsRequireNewConfirmation() {
        XCTAssertNotNil(Stopper.refusal(expected: row(), current: row(ports: ["*:4520", "*:9000"]), protected: false))
    }
    func testRememberedProtectionOverridesSelection() {
        XCTAssertNotNil(Stopper.refusal(expected: row(), current: row(), protected: true))
    }
    func testUnchangedIdentityIsAllowed() {
        XCTAssertNil(Stopper.refusal(expected: row(), current: row(), protected: false))
    }
    func testMissingProcessIsNotSignalled() {
        XCTAssertNotNil(Stopper.refusal(expected: row(), current: nil, protected: false))
    }
    func testSystemProcessCannotBeStopped() {
        var system = row(); system.executable = "/usr/libexec/rapportd"
        XCTAssertNotNil(Stopper.refusal(expected: system, current: system, protected: false))
    }
    func testProtectionsDistinguishDifferentProjects() {
        var other = row(); other.directory = "/tmp/another-project"
        XCTAssertNotEqual(row().protectionKey, other.protectionKey)
    }
    func testJevPayloadContainsNoFullPathsOrCommandArguments() throws {
        let data = try Jev.payload(rows: [row()], rules: "Keep my daily tools.")
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(text.contains("/tmp/project"))
        XCTAssertFalse(text.contains("/opt/homebrew"))
        XCTAssertTrue(text.contains("project"))
        XCTAssertTrue(text.contains("jev-latest"))
        let root = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let questions = root["questions"] as! [String: [String: Any]]
        XCTAssertEqual(questions.count, 2)
        XCTAssertNotNil(questions["p43210"]?["criteria"])
        XCTAssertNil(questions["p43210"]?["choices"])
    }
    func testInvalidOrMissingAnswersFailClosed() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"kill_everything","confidence":1}}}"#.utf8)
        let result = try Jev.decode(data, rows: [row()])
        XCTAssertEqual(result[43210]?.decision, .uncertain)
    }
    func testLowConfidenceCleanupBecomesUncertain() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"cleanup","confidence":0.3,"probabilities":{"keep":0.3,"cleanup":0.4,"uncertain":0.3}}}}"#.utf8)
        XCTAssertEqual(try Jev.decode(data, rows: [row()])[43210]?.decision, .uncertain)
    }
    func testConfidentTypedDecisionIsAccepted() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"cleanup","confidence":0.95,"probabilities":{"keep":0.01,"cleanup":0.98,"uncertain":0.01}},"r43210":{"type":"choice","choice":"temporary_preview"}}}"#.utf8)
        let answer = try Jev.decode(data, rows: [row()])[43210]
        XCTAssertEqual(answer?.decision, .cleanup)
        XCTAssertEqual(answer?.reason, "Temporary preview")
    }
    func testMalformedTopLevelIsRejected() {
        do { _ = try Jev.decode(Data("{}".utf8), rows: [row()]); preconditionFailure("Malformed response accepted") } catch {}
    }
    func testWrongOwnerCannotBeStopped() {
        var other = row(); other.uid = getuid() + 1
        XCTAssertNotNil(Stopper.refusal(expected: other, current: other, protected: false))
    }
    func testSelfCannotBeStopped() {
        var own = row(); own.pid = getpid()
        XCTAssertNotNil(Stopper.refusal(expected: own, current: own, protected: false))
    }
    func testProbabilityShapeIsValidated() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"cleanup","confidence":0.99,"probabilities":{"cleanup":0.99}}}}"#.utf8)
        XCTAssertEqual(try Jev.decode(data, rows: [row()])[43210]?.decision, .uncertain)
    }
    func testConfidentUncertaintyIsNotCalledLowConfidence() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"uncertain","confidence":0.95,"probabilities":{"keep":0.01,"cleanup":0.01,"uncertain":0.98}},"r43210":{"type":"choice","choice":"unknown_intent"}}}"#.utf8)
        let answer = try Jev.decode(data, rows: [row()])[43210]
        XCTAssertEqual(answer?.reason, "Still needed? Your intent is missing")
        XCTAssertEqual(answer?.modelDecision, .uncertain)
        XCTAssertFalse(answer?.reviewCause?.contains("low confidence") ?? true)
    }
    func testInvalidResponseHasSpecificReviewCause() throws {
        let answer = try Jev.decode(Data(#"{"answers":{}}"#.utf8), rows: [row()])[43210]
        XCTAssertEqual(answer?.reason, "Invalid or missing Jev answer")
        XCTAssertNil(answer?.modelDecision)
    }
    func testSafetyGateDoesNotEraseModelRecommendation() throws {
        let data = Data(#"{"answers":{"p43210":{"type":"choice","choice":"cleanup","confidence":0.7,"probabilities":{"keep":0.03,"cleanup":0.94,"uncertain":0.03}},"r43210":{"type":"choice","choice":"temporary_preview"}}}"#.utf8)
        let answer = try Jev.decode(data, rows: [row()])[43210]
        XCTAssertEqual(answer?.decision, .uncertain)
        XCTAssertEqual(answer?.modelDecision, .cleanup)
        XCTAssertEqual(answer?.reason, "Cleanup suggestion below safety threshold")
        XCTAssertTrue(answer?.reviewCause?.contains("Temporary preview") ?? false)
    }
    func testConflictingTypedAnswersAreFlagged() throws {
        for choice in ["uncertain", "cleanup"] {
            let data = Data("{\"answers\":{\"p43210\":{\"type\":\"choice\",\"choice\":\"\(choice)\",\"confidence\":0.9,\"probabilities\":{\"keep\":0.01,\"cleanup\":0.98,\"uncertain\":0.01}},\"r43210\":{\"type\":\"choice\",\"choice\":\"daily_service\"}}}".utf8)
            let answer = try Jev.decode(data, rows: [row()])[43210]
            XCTAssertEqual(answer?.decision, .uncertain)
            XCTAssertEqual(answer?.reason, "Jev's verdict and reason disagree")
        }
    }
    func testFinishedIntentIsBoundToProcessLifetimeAndPortSet() throws {
        let original = row()
        XCTAssertNotEqual(original.intentKey, row(start: 12).intentKey)
        XCTAssertNotEqual(original.intentKey, row(ports: ["*:9900"]).intentKey)
        let data = try Jev.payload(rows: [original, row(pid: 43211)], rules: "Keep my tools", finished: [original.intentKey])
        let root = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let state = root["state"] as! [String: Any]
        let rows = state["processes"] as! [[String: Any]]
        XCTAssertEqual(rows[0]["user_confirmed_finished"] as? Bool, true)
        XCTAssertEqual(rows[1]["user_confirmed_finished"] as? Bool, false)
    }
    func testLiveDisposableProcessCleanup() throws {
        func launch() throws -> Process {
            let p = Process(); let pipe = Pipe()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            p.arguments = ["-u", "-c", "import socket,time\ns=[socket.socket(),socket.socket()]\nfor x in s: x.bind(('127.0.0.1',0)); x.listen()\nprint('ready',flush=True)\ntime.sleep(60)"]
            p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
            try p.run()
            guard String(decoding: pipe.fileHandleForReading.availableData, as: UTF8.self).contains("ready") else { if p.isRunning { p.terminate() }; p.waitUntilExit(); throw PortError("Disposable fixture did not start") }
            return p
        }
        let selected = try launch(); defer { if selected.isRunning { selected.terminate() }; selected.waitUntilExit() }
        let selected2 = try launch(); defer { if selected2.isRunning { selected2.terminate() }; selected2.waitUntilExit() }
        let untouched = try launch(); defer { if untouched.isRunning { untouched.terminate() }; untouched.waitUntilExit() }
        guard let row = try Scanner.scan().first(where: { $0.pid == selected.processIdentifier }) else { throw PortError("Fixture not discovered") }
        guard row.endpoints.count == 2 else { throw PortError("Did not discover both fixture ports") }
        let protected = try Stopper.stop([row], protections: [row.protectionKey])
        guard protected.first?.stopped == false, selected.isRunning else { throw PortError("Protection failed") }
        var stale = row; stale.start += 1
        let reused = try Stopper.stop([stale], protections: [])
        guard reused.first?.stopped == false, selected.isRunning else { throw PortError("PID identity protection failed") }
        var changed = row; changed.endpoints.append("127.0.0.1:1")
        let mismatch = try Stopper.stop([changed], protections: [])
        guard mismatch.first?.stopped == false, selected.isRunning else { throw PortError("Changed endpoint protection failed") }
        guard let row2 = try Scanner.scan().first(where: { $0.pid == selected2.processIdentifier }) else { throw PortError("Second selected fixture not discovered") }
        let results = try Stopper.stop([row, row2], protections: [])
        selected.waitUntilExit()
        selected2.waitUntilExit()
        let after = try Scanner.scan()
        guard results.count == 2, results.allSatisfy(\.stopped), !after.contains(where: { $0.pid == row.pid || $0.pid == row2.pid }), untouched.isRunning, after.contains(where: { $0.pid == untouched.processIdentifier }) else { throw PortError("Selected-process shutdown or unselected-process isolation failed") }
        print("INTEGRATION: two selected disposable PIDs \(row.pid), \(row2.pid), four ports \((row.ports + row2.ports).joined(separator: ", ")) stopped; unselected fixture preserved; protection, identity and endpoint guards exercised")
    }
}

@main struct CheckRunner {
    static func main() throws {
        let t = CoreTests()
        t.testParserGroupsAllSocketsWithoutDuplicates()
        t.testPIDReuseIsNeverAllowed()
        t.testChangedPortsRequireNewConfirmation()
        t.testRememberedProtectionOverridesSelection()
        t.testUnchangedIdentityIsAllowed()
        t.testMissingProcessIsNotSignalled()
        t.testSystemProcessCannotBeStopped()
        t.testProtectionsDistinguishDifferentProjects()
        try t.testJevPayloadContainsNoFullPathsOrCommandArguments()
        try t.testInvalidOrMissingAnswersFailClosed()
        try t.testLowConfidenceCleanupBecomesUncertain()
        try t.testConfidentTypedDecisionIsAccepted()
        t.testMalformedTopLevelIsRejected()
        t.testWrongOwnerCannotBeStopped()
        t.testSelfCannotBeStopped()
        try t.testProbabilityShapeIsValidated()
        try t.testConfidentUncertaintyIsNotCalledLowConfidence()
        try t.testInvalidResponseHasSpecificReviewCause()
        try t.testSafetyGateDoesNotEraseModelRecommendation()
        try t.testConflictingTypedAnswersAreFlagged()
        try t.testFinishedIntentIsBoundToProcessLifetimeAndPortSet()
        try t.testLiveDisposableProcessCleanup()
        let evidenceChecks = try runEvidenceChecks()
        let inspectionChecks = try runInspectionChecks()
        let bulkChecks = try runBulkChecks()
        print("PASS: \(22 + evidenceChecks + inspectionChecks + bulkChecks) checks including live bulk shutdown and unselected-process isolation")
    }
}
