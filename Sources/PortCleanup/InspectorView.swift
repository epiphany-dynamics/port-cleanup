import SwiftUI
import PortCore

struct InspectorView: View {
    let row: Listener
    @ObservedObject var model: PortModel
    @Environment(\.dismiss) private var dismiss
    @ViewState private var report: InspectionReport?
    @ViewState private var interpretation: EvidenceInterpretation?
    @ViewState private var busy = false
    @ViewState private var error: String?
    init(row: Listener, model: PortModel, initialReport: InspectionReport? = nil, initialInterpretation: EvidenceInterpretation? = nil) {
        self.row = row; self.model = model; _report = ViewState(initialValue: initialReport)
        _interpretation = ViewState(initialValue: initialInterpretation)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Label("Port \(row.ports.joined(separator: ", "))", systemImage: "network").font(.system(size: 24, weight: .semibold, design: .rounded))
                    Text("\(row.appName) · PID \(row.pid) · \(row.project)").foregroundStyle(.secondary)
                    if let report, report.startup.headless {
                        Text("\(report.startup.headless ? "Headless browser · " : "")\(report.startup.profilePath.map { "Profile \(URL(fileURLWithPath: $0).lastPathComponent) · " } ?? "")\(report.pages.filter { $0.type == "page" }.count) observed page targets").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Refresh evidence") { load() }.disabled(busy).buttonStyle(.bordered)
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).buttonStyle(.borderedProminent)
            }
            if let error { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).textSelection(.enabled) }
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if let r = report {
                        section("Launch history · why this process was created", icon: "clock.arrow.circlepath") {
                            Text(r.launchHistory.status).font(.callout)
                            if let task = r.launchHistory.task { detail("Likely originating task (local history)", task) }
                            if let session = r.launchHistory.sessionID { detail("Hermes session", session) }
                            if let ended = r.launchHistory.sessionEndedAt {
                                Label("Originating session closed \(Date(timeIntervalSince1970: ended).formatted(date: .abbreviated, time: .standard))", systemImage: "exclamationmark.circle").foregroundStyle(.orange)
                                Text("Recorded reason: \(r.launchHistory.endReason ?? "unspecified"). Closed does not mean the task succeeded or that nobody reused this process.").font(.caption).foregroundStyle(.secondary)
                            }
                            Text(r.launchHistory.laterReuse).font(.caption).foregroundStyle(.secondary)
                        }
                        section("1 · Owner and startup", icon: "terminal") {
                            detail("Executable", r.process.executable)
                            detail("Working project folder", r.process.directory)
                            detail("Started", Date(timeIntervalSince1970: Double(r.process.start) / 1_000_000).formatted(date: .abbreviated, time: .standard))
                            detail("Parent", r.process.parent == 1 ? "PID 1 · original parent is gone or process was daemonized. This does not prove abandonment." : "PID \(r.process.parent) · \(r.process.ancestors.joined(separator: " ← "))")
                            detail("Startup arguments (safe subset)", r.startup.available ? r.startup.safeArguments.isEmpty ? "No allowlisted startup arguments identified; raw command was not exposed." : r.startup.safeArguments.joined(separator: " ") : "Unavailable")
                            detail("All listening addresses", r.process.endpoints.joined(separator: ", "))
                            if let label = r.process.evidence?.launchdLabel { detail("Service registration", "\(label) · registration is not proof this work is still needed") }
                        }
                        section("2 · What is connected to it", icon: "point.3.connected.trianglepath.dotted") {
                            Text(r.peerStatus).font(.callout)
                            ForEach(r.peers, id: \.process.pid) { peer in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("PID \(peer.process.pid) · \(peer.process.appName)").bold()
                                    detail("Executable", peer.process.executable)
                                    detail("Startup", peer.startup.safeArguments.joined(separator: " ").isEmpty ? "No allowlisted arguments found" : peer.startup.safeArguments.joined(separator: " "))
                                    detail("Folder", peer.process.directory)
                                    detail("Parent app", "\(peer.parentApp ?? "Unavailable") · PID \(peer.process.parent)")
                                    detail("Started", Date(timeIntervalSince1970: Double(peer.process.start) / 1_000_000).formatted(date: .abbreviated, time: .standard))
                                    if let session = peer.harnessSession { detail("Browser harness session", "\(session) · this is a tool-session name, not a verified agent conversation") }
                                }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.quaternary.opacity(0.35)).cornerRadius(8)
                            }
                            Text("A browser controller or another browser can remain connected after the original task ends. Connected ≠ currently needed.").foregroundStyle(.orange).font(.callout)
                        }
                        section("3 · Actual browser workload and linked servers", icon: "globe") {
                            Text(r.browserStatus).font(.callout).foregroundStyle(.secondary)
                            ForEach(Array(r.pages.enumerated()), id: \.offset) { _, page in
                                detail("\(page.type) · \(page.title)", page.origin)
                            }
                            ForEach(r.relatedServers) { server in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Page points to port \(server.ports.joined(separator: ", ")) · server PID \(server.pid)").bold()
                                    Text(server.directory).font(.callout).textSelection(.enabled)
                                    Text("Separate server process. Stopping this browser does not directly stop that server.").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        section("4 · What is still unknown", icon: "questionmark.circle") {
                            ForEach(r.unknowns, id: \.self) { Text("• \($0)").font(.callout) }
                            Text("Nothing above proves this is a stale port or guarantees it is safe to close. These are the facts for your decision.").font(.callout).foregroundStyle(.orange)
                        }
                        section("5 · Jev's recommendation and reason", icon: "sparkles") {
                            if let interpretation {
                                Text(model.protected(row) ? "Keep open · protected" : interpretation.label).font(.title3.bold()).foregroundStyle(model.protected(row) ? Color.green : interpretation.verdict == .cleanup ? Color.red : interpretation.verdict == .keep ? Color.green : Color.orange)
                                Text(interpretation.reason).font(.body)
                                Text(interpretation.missingFact).foregroundStyle(.orange)
                                Text("Evidence-backed recommendation, not a guarantee. You confirm every shutdown.").font(.caption).foregroundStyle(.secondary)
                            } else { Text("Jev receives this inspection, including startup context, named peers and the local browser workload—not merely app names and socket counts.").font(.callout) }
                            Button("Interpret this evidence with Jev") { interpret() }.buttonStyle(.borderedProminent).tint(.green).disabled(busy)
                            Text("One paid request per click. Sends minimized evidence, launch-session status and local page titles; full paths, task/transcript text, raw commands, remote page details and secrets are withheld. No automatic shutdown.").font(.caption).foregroundStyle(.secondary)
                        }
                        section("If you choose to stop it", icon: "exclamationmark.triangle") {
                            Text("Only PID \(r.process.pid) receives a graceful stop request. All its listening ports and connections close; the connected clients above may lose their browser connection. Separate preview servers are not directly signalled. Unsaved work in this process may be lost.").font(.callout)
                        }
                        Text("Collected \(r.collectedAt.formatted(date: .abbreviated, time: .standard)). Snapshot only; refresh to check again.").font(.caption).foregroundStyle(.secondary)
                    } else { Text(busy ? "Collecting process, peer and workload evidence…" : "No inspection available.").padding(24) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            HStack {
                Text("You decide. Inspection never stops a process.").foregroundStyle(.secondary)
                Spacer()
                Button("Select this process for cleanup") { model.selected.insert(row.pid); dismiss() }.disabled(busy || report == nil || model.protected(row)).buttonStyle(.bordered)
            }
        }.padding(24).frame(minWidth: 760, maxWidth: 940, minHeight: 680, maxHeight: 920)
        .task { if report == nil { load() } }
    }
    @ViewBuilder private func section<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) { Label(title, systemImage: icon).font(.headline); content() }
    }
    private func detail(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) { Text(title).font(.caption).foregroundStyle(.secondary); Text(value).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
    }
    private func load() {
        guard !busy else { return }; busy = true; error = nil; interpretation = nil; report = nil
        model.interpretations.removeValue(forKey: row.pid)
        Task {
            defer { busy = false }
            do { let result = try await Inspection.collect(row); report = result; model.inspections[row.pid] = result }
            catch { self.error = error.localizedDescription }
        }
    }
    private func interpret() {
        guard !busy else { return }; busy = true; error = nil; interpretation = nil
        Task {
            defer { busy = false }
            do {
                let fresh = try await Inspection.collect(row); report = fresh; model.inspections[row.pid] = fresh
                interpretation = try await JevEvidence.interpret(fresh, protected: model.protected(row))
                model.interpretations[row.pid] = interpretation
            } catch { self.error = error.localizedDescription }
        }
    }
}
