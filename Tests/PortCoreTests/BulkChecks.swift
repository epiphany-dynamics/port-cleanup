import Foundation
import PortCore

func runBulkChecks() throws -> Int {
    func report(_ pid: Int32) throws -> InspectionReport {
        let row = Listener(pid: pid, name: "node", executable: "/tmp/PRIVATE/node", directory: "/tmp/PRIVATE/project", uid: getuid(), start: 123, parent: 1, ancestors: [], endpoints: ["127.0.0.1:1234"])
        let object: [String: Any] = ["collectedAt": 0, "process": try JSONSerialization.jsonObject(with: JSONEncoder().encode(row)), "startup": try JSONSerialization.jsonObject(with: JSONEncoder().encode(StartupDetails.parse(["node"]))), "peers": [], "peerStatus": "none observed", "pages": [], "browserStatus": "not probed", "relatedServers": [], "launchHistory": ["status": "fixture", "laterReuse": "unknown"], "unknowns": ["intent unknown"]]
        return try JSONDecoder().decode(InspectionReport.self, from: JSONSerialization.data(withJSONObject: object))
    }
    let reports = try [report(91001), report(91002)]
    let payload = try JevEvidence.batchPayload(reports, protectedPIDs: [91002])
    let root = try JSONSerialization.jsonObject(with: payload) as! [String: Any]
    let questions = root["questions"] as! [String: [String: Any]]
    precondition(questions.count == 4)
    precondition((questions["p91001_context"]?["instructions"] as? String)?.contains("processes.p91001") == true)
    precondition((questions["p91002_context"]?["instructions"] as? String)?.contains("processes.p91002") == true)
    let state = root["state"] as! [String: Any]
    precondition((state["processes"] as? [String: Any])?.count == 2)
    let processes = state["processes"] as! [String: [String: Any]]
    precondition(processes["p91002"]?["user_protected"] as? Bool == true && processes["p91001"]?["user_protected"] as? Bool == false)
    precondition(!String(decoding: payload, as: UTF8.self).contains("/tmp/PRIVATE"))
    do { _ = try JevEvidence.batchPayload([reports[0], reports[0]]); preconditionFailure("Duplicate PID must fail") } catch {}
    func answer(_ choice: String, criteria: [String: String]) -> [String: Any] { ["type": "choice", "choice": choice, "confidence": 1, "probabilities": Dictionary(uniqueKeysWithValues: criteria.keys.map { ($0, $0 == choice ? 1.0 : 0.0) })] }
    let fixture: [String: Any] = ["answers": ["p91001_context": answer("review_current_need", criteria: JevEvidence.contexts), "p91001_missing_fact": answer("originating_task", criteria: JevEvidence.gaps)]]
    let result = try JevEvidence.decodeBatch(JSONSerialization.data(withJSONObject: fixture), reports: reports)
    precondition(result.results.count == 1 && result.results[91001] != nil && result.errors.count == 1 && result.errors[91002] != nil)
    let unsafe = try JevEvidence.decode(JSONSerialization.data(withJSONObject: ["answers": ["context": answer("kill_closed_isolated_tool", criteria: JevEvidence.contexts), "missing_fact": answer("later_reuse", criteria: JevEvidence.gaps)]]))
    precondition(JevEvidence.validate(unsafe, report: reports[0]).verdict == .uncertain)
    precondition(JevEvidence.validate(unsafe, report: reports[0], protected: true).verdict == .keep)
    return 5
}
