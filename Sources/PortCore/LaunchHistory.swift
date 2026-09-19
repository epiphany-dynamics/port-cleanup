import Foundation

public struct LaunchHistory: Codable, Sendable {
    public let status: String
    public let sessionID: String?
    public let task: String?
    public let launchedAt: Double?
    public let sessionEndedAt: Double?
    public let endReason: String?
    public let messageID: Int?
    public let laterReuse: String
    public var minimized: [String: Any] {
        ["status": status, "source": "default-profile Hermes history; no other agents searched", "session_id": sessionID as Any? ?? NSNull(), "matched_launch_timestamp": launchedAt as Any? ?? NSNull(), "originating_session_ended_at": sessionEndedAt as Any? ?? NSNull(), "end_reason": endReason as Any? ?? NSNull(), "later_reuse": laterReuse]
    }
}
public enum LaunchHistoryReader {
    public static func quote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "''") + "'" }
    public static func lookup(process: Listener, startup: StartupDetails) -> LaunchHistory {
        func absent(_ status: String) -> LaunchHistory { LaunchHistory(status: status, sessionID: nil, task: nil, launchedAt: nil, sessionEndedAt: nil, endReason: nil, messageID: nil, laterReuse: "Not established. A later task could reuse an existing listener.") }
        // Strong, process-lifetime-specific markers only; never a global port-number search.
        guard startup.headless, let profile = startup.profilePath, let port = startup.debugPort else { return absent("No supported launch-history signature for this process. Current adapter covers isolated headless-browser launches in default-profile Hermes history only.") }
        let db = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hermes/state.db")
        guard FileManager.default.fileExists(atPath: db.path) else { return absent("Default-profile Hermes history is unavailable.") }
        let start = Double(process.start) / 1_000_000
        let query = """
        SELECT s.id AS sessionID, m.id AS messageID, m.timestamp AS launchedAt, s.ended_at AS sessionEndedAt, s.end_reason AS endReason,
        coalesce(s.title,(SELECT substr(content,1,240) FROM messages WHERE session_id=s.id AND role='user' ORDER BY timestamp,id LIMIT 1)) AS task
        FROM messages m JOIN sessions s ON s.id=m.session_id
        WHERE m.role='assistant' AND m.timestamp BETWEEN \(start - 15) AND \(start + 15) AND s.started_at <= \(start + 1)
        AND instr(coalesce(m.tool_calls,''),\(quote(profile)))>0 AND instr(coalesce(m.tool_calls,''),\(quote("--remote-debugging-port=\(port)")))>0
        AND json_valid(m.tool_calls) AND EXISTS (SELECT 1 FROM json_each(m.tool_calls) t WHERE json_extract(t.value,'$.function.name') IN ('terminal','execute_code'))
        ORDER BY s.started_at DESC, abs(m.timestamp-\(start)) ASC LIMIT 1;
        """
        let task = Process(); task.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3"); task.arguments = ["-readonly", "-json", db.path, query]
        let pipe = Pipe(); task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { return absent("History reader could not start; no session ownership inferred.") }
        let deadline = Date().addingTimeInterval(2)
        while task.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if task.isRunning { task.terminate(); return absent("History lookup exceeded its time limit; no session ownership inferred.") }
        guard task.terminationStatus == 0 else { return absent("History database was busy or its schema was unavailable; no session ownership inferred.") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let list = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]], let row = list.first, let sessionID = row["sessionID"] as? String else { return absent("No launch record matched this profile path and port within 15 seconds of this process starting. This is not proof no agent owns it.") }
        return LaunchHistory(status: "Strong launch-history match: exact browser profile + debugging port, within 15 seconds of process start. Correlation, not a kernel-recorded owner ID.", sessionID: sessionID, task: row["task"] as? String, launchedAt: row["launchedAt"] as? Double, sessionEndedAt: row["sessionEndedAt"] as? Double, endReason: row["endReason"] as? String, messageID: row["messageID"] as? Int, laterReuse: "Not ruled out. The originating session closing does not establish that another session never reused this browser. No global last-command log was found or inferred.")
    }
}
