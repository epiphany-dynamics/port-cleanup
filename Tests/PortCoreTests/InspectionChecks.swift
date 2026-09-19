import Foundation
import PortCore

func runInspectionChecks() throws -> Int {
    let startup = StartupDetails.parse(["chrome", "--headless=new", "--remote-debugging-port=9224", "--user-data-dir=/tmp/private/pgdev-chrome", "--password=DO_NOT_EXPOSE", "https://example.com/?token=DO_NOT_EXPOSE"])
    precondition(startup.headless && startup.debugPort == 9224 && startup.profilePath == "/tmp/private/pgdev-chrome")
    precondition(!startup.safeArguments.joined().contains("DO_NOT_EXPOSE"))
    let python = StartupDetails.parse(["python", "-m", "browser_harness.daemon", "--token", "DO_NOT_EXPOSE"])
    precondition(python.module == "browser_harness.daemon" && !python.safeArguments.joined().contains("DO_NOT_EXPOSE"))
    let inline = StartupDetails.parse(["python", "-c", "print('DO_NOT_EXPOSE')"])
    precondition(inline.module == nil && inline.scriptPath == nil && inline.safeArguments.isEmpty)
    let noPort = StartupDetails.parse(["chrome", "--remote-debugging-port=99999"])
    precondition(noPort.debugPort == nil)
    let tunnel = StartupDetails.parse(["/usr/bin/ssh", "-N", "-L", "127.0.0.1:9223:127.0.0.1:9222", "epiphany"])
    precondition(tunnel.sshForwards == ["127.0.0.1:9223:127.0.0.1:9222"] && tunnel.sshDestination == "epiphany")
    precondition(LaunchHistoryReader.quote("/tmp/a'b") == "'/tmp/a''b'")
    let pages = try Inspection.parsePages(Data(#"[{"type":"page","title":"Patrick Gibbs | AI Systems","url":"http://127.0.0.1:4520/private?token=DO_NOT_EXPOSE"},{"type":"page","title":"DO_NOT_EXPOSE","url":"https://private.example/account?key=DO_NOT_EXPOSE"},{"type":"service_worker","title":"worker","url":"chrome-extension://abcdef/bg.js"}]"#.utf8))
    precondition(pages.count == 3 && pages[0].localPort == 4520 && pages[0].title == "Patrick Gibbs | AI Systems")
    precondition(pages[0].origin == "http://127.0.0.1:4520" && pages[1].title == "Remote page (title withheld)")
    let encodedPages = try JSONEncoder().encode(pages)
    precondition(!String(decoding: encodedPages, as: UTF8.self).contains("DO_NOT_EXPOSE"))
    do { _ = try Inspection.parsePages(Data("{}".utf8)); preconditionFailure("Malformed targets must throw") } catch {}
    func answer(_ chosen: String, _ criteria: [String: String]) -> [String: Any] { ["type": "choice", "choice": chosen, "confidence": 1.0, "probabilities": Dictionary(uniqueKeysWithValues: criteria.keys.map { ($0, $0 == chosen ? 1.0 : 0.0) })] }
    let fixture: [String: Any] = ["answers": ["context": answer("kill_closed_isolated_tool", JevEvidence.contexts), "missing_fact": answer("later_reuse", JevEvidence.gaps)]]
    let interpreted = try JevEvidence.decode(JSONSerialization.data(withJSONObject: fixture))
    precondition(interpreted.verdict == .cleanup && interpreted.label == "Kill recommended" && interpreted.explanation.contains("originating agent session closed"))
    for (choice, verdict, label) in [("keep_live_owner", Decision.keep, "Keep open"), ("review_current_need", Decision.uncertain, "Your decision")] {
        let fixture: [String: Any] = ["answers": ["context": answer(choice, JevEvidence.contexts), "missing_fact": answer("originating_task", JevEvidence.gaps)]]
        let result = try JevEvidence.decode(JSONSerialization.data(withJSONObject: fixture))
        precondition(result.verdict == verdict && result.label == label)
    }
    var low = answer("kill_closed_isolated_tool", JevEvidence.contexts); low["confidence"] = 0.5
    let withheld = try JevEvidence.decode(JSONSerialization.data(withJSONObject: ["answers": ["context": low, "missing_fact": answer("later_reuse", JevEvidence.gaps)]]))
    precondition(withheld.verdict == .uncertain && withheld.reason.contains("below the safety threshold"))
    do { _ = try JevEvidence.decode(Data(#"{"answers":{"context":{"type":"choice","choice":"kill"}}}"#.utf8)); preconditionFailure("Kill is not a valid context") } catch {}
    return 14
}
