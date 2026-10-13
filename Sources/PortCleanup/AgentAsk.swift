import AppKit
import Foundation
import PortCore

enum LocalAgent: String, CaseIterable, Identifiable {
    case claudeCode = "claude"
    case codex = "codex"
    case hermes = "hermes"

    var id: String { rawValue }
    var title: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .codex: return "Codex"
        case .hermes: return "Hermes"
        }
    }
    var commandName: String { rawValue }
}

enum AskFacts {
    static func clientLabel(_ row: Listener) -> String {
        guard row.evidence?.establishedScanStatus == "available" else { return "activity unavailable" }
        return "\(row.evidence?.inboundCount ?? 0) listener clients"
    }

    static func startedLabel(_ row: Listener) -> String {
        guard row.start > 0 else { return "unknown" }
        return Date(timeIntervalSince1970: Double(row.start) / 1_000_000).formatted(date: .omitted, time: .shortened)
    }

    static func snapshot(_ row: Listener, status: String, detail: String, selected: Bool) -> AskSnapshot {
        AskSnapshot(
            appName: publicLabel(row.appName, fallback: "Unknown app"),
            processName: publicLabel(row.name, fallback: "Unknown process"),
            pid: row.pid,
            ports: row.ports,
            project: publicLabel(row.project, fallback: "Unknown folder"),
            clientLabel: clientLabel(row),
            started: startedLabel(row),
            status: publicLabel(status, fallback: "Not analyzed yet"),
            detail: publicLabel(detail, fallback: ""),
            selected: selected
        )
    }

    private static func publicLabel(_ value: String, fallback: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("\n"), !trimmed.contains("\0") else { return fallback }
        let kept = trimmed.split(separator: " ").filter { !$0.contains("/") }.joined(separator: " ")
        return kept.isEmpty ? fallback : kept
    }
}

struct AskSnapshot: Equatable {
    var appName: String
    var processName: String
    var pid: Int32
    var ports: [String]
    var project: String
    var clientLabel: String
    var started: String
    var status: String
    var detail: String
    var selected: Bool
}

enum AskBrief {
    static func text(rows: [AskSnapshot]) -> String {
        let selected = rows.filter(\.selected)
        let focus = selected.isEmpty
            ? "Answer about the full current scan."
            : "Answer about the selected rows first, then the rest of the scan."
        var lines = [
            "Port Cleanup scan",
            "This is the on-screen summary only. It has no command lines, environment values, full paths, or secrets.",
            "Do not stop, signal, kill, or restart any process. Do not edit files. Answer questions only.",
            focus,
            "Rows: \(rows.count). Selected: \(selected.count).",
            ""
        ]
        if rows.isEmpty {
            lines.append("No listening ports were in this scan.")
            return lines.joined(separator: "\n")
        }
        for row in rows {
            let mark = row.selected ? "selected" : "not selected"
            let ports = row.ports.joined(separator: ", ")
            let detail = row.detail.isEmpty ? row.status : "\(row.status). \(row.detail)"
            lines.append("- \(row.appName) | \(row.processName) | PID \(row.pid) | ports \(ports) | project \(row.project) | \(row.clientLabel) | started \(row.started) | \(mark) | \(detail)")
        }
        lines.append("")
        lines.append("Start by saying what must stay open and what looks safe to stop. Then wait for the next question.")
        return lines.joined(separator: "\n")
    }

    static func leaks(brief: String, directories: [String], executables: [String]) -> [String] {
        var hits: [String] = []
        for path in directories where path.contains("/") && brief.contains(path) {
            hits.append("directory")
        }
        for path in executables where path.contains("/") && brief.contains(path) {
            hits.append("executable")
        }
        return Array(Set(hits)).sorted()
    }
}

enum AskError: LocalizedError {
    case notInstalled(String)
    case unusablePath(String)
    case couldNotWrite

    var errorDescription: String? {
        switch self {
        case .notInstalled(let title): return "\(title) is not installed on this Mac. Nothing was opened and nothing was stopped."
        case .unusablePath(let title): return "\(title) was found, but its path cannot be opened safely. Nothing was opened and nothing was stopped."
        case .couldNotWrite: return "Could not prepare the question. Nothing was opened and nothing was stopped."
        }
    }
}

enum AgentLaunch {
    static func resolve(_ agent: LocalAgent) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [agent.commandName]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = Pipe()
        do { try process.run() } catch { return nil }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let path = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let path, path.hasPrefix("/"), !path.contains("\n"), !path.contains("\0") else { return nil }
        return path
    }

    static func prepare(agent: LocalAgent, brief: String) throws -> URL {
        guard let executable = resolve(agent) else { throw AskError.notInstalled(agent.title) }
        guard executable.hasPrefix("/") else { throw AskError.unusablePath(agent.title) }
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("port-cleanup-ask-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try brief.write(to: folder.appendingPathComponent("BRIEF.md"), atomically: true, encoding: .utf8)
            try agent.rawValue.write(to: folder.appendingPathComponent("agent.txt"), atomically: true, encoding: .utf8)
            try executable.write(to: folder.appendingPathComponent("executable.txt"), atomically: true, encoding: .utf8)
            let launcher = folder.appendingPathComponent("launch.py")
            try Self.launcherSource.write(to: launcher, atomically: true, encoding: .utf8)
            let command = folder.appendingPathComponent("Ask.command")
            try "#!/bin/bash\nset -euo pipefail\ncd \"$(dirname \"$0\")\"\nexec /usr/bin/python3 launch.py\n".write(to: command, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: command.path)
            return command
        } catch {
            throw AskError.couldNotWrite
        }
    }

    static func open(_ command: URL) {
        NSWorkspace.shared.open(command)
    }

    static func openedMessage(_ agent: LocalAgent) -> String {
        switch agent {
        case .claudeCode:
            return "Opened Claude Code with this scan. Its command tools are off. Nothing was stopped."
        case .codex:
            return "Opened Codex in read-only mode with this scan. It was told not to stop anything, and it asks before running a command. Nothing was stopped."
        case .hermes:
            return "Opened Hermes with this scan. Process tools are off for that window. Nothing was stopped."
        }
    }

    private static let launcherSource = """
    import os
    import pathlib
    import sys

    root = pathlib.Path(__file__).resolve().parent
    agent = (root / "agent.txt").read_text(encoding="utf-8").strip()
    executable = (root / "executable.txt").read_text(encoding="utf-8").strip()
    brief = str(root / "BRIEF.md")
    question = (
        "Explain this Port Cleanup scan. What must stay open, and what looks safe to stop? "
        "Do not stop, signal, kill, or restart any process. Do not edit files. Then wait for the next question."
    )
    if agent == "claude":
        os.execv(executable, [
            executable,
            "--append-system-prompt-file", brief,
            "--tools", "",
            "--strict-mcp-config",
            "--permission-mode", "default",
            question,
        ])
    if agent == "codex":
        os.chdir(root)
        os.execv(executable, [
            executable,
            "-s", "read-only",
            "-a", "on-request",
            "-C", str(root),
            "--skip-git-repo-check",
            "Read BRIEF.md in this folder. It is a Port Cleanup scan with no command lines, full paths, or secrets. " + question,
        ])
    if agent == "hermes":
        os.execv(executable, [executable, "chat", "--query-file", brief, "-t", "clarify"])
    sys.exit("Unknown agent")
    """
}
