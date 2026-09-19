import SwiftUI
import AppKit
import PortCore

// SDK 27 adds a same-named macro unavailable in Command Line Tools.
// A type alias explicitly selects the supported property wrapper.
typealias ViewState<Value> = SwiftUI.State<Value>

@MainActor final class PortModel: ObservableObject {
    @Published var rows: [Listener] = []
    @Published var inspectionTarget: Listener?
    @Published var inspections: [Int32: InspectionReport] = [:]
    @Published var interpretations: [Int32: EvidenceInterpretation] = [:]
    @Published var inspectionErrors: [Int32: String] = [:]
    @Published var requestedPIDs: [Int32] = []
    @Published var selected: Set<Int32> = []
    @Published var recommendations: [Int32: Recommendation] = [:]
    @Published var busy = false
    @Published var message = "Ready. Nothing stops without your confirmation."
    @Published var failure: String?
    @Published var protections: Set<String>
    @Published var finished: Set<String>
    @Published var history: [String]
    @Published var rules: String {
        didSet { UserDefaults.standard.set(rules, forKey: "jevRules"); recommendations = [:]; selected = [] }
    }
    private let defaults = UserDefaults.standard
    init() {
        protections = Set(UserDefaults.standard.stringArray(forKey: "protections") ?? [])
        finished = Set(UserDefaults.standard.stringArray(forKey: "finished") ?? [])
        history = UserDefaults.standard.stringArray(forKey: "history") ?? []
        let savedRules = UserDefaults.standard.string(forKey: "jevRules")
        rules = savedRules == Jev.previousDefaultRules ? Jev.defaultRules : savedRules ?? Jev.defaultRules
    }
    func protected(_ row: Listener) -> Bool { row.hardProtection != nil || protections.contains(row.protectionKey) }
    func toggleProtection(_ row: Listener) {
        if protections.contains(row.protectionKey) { protections.remove(row.protectionKey) } else { protections.insert(row.protectionKey); selected.remove(row.pid); finished.remove(row.intentKey) }
        defaults.set(Array(protections), forKey: "protections")
        defaults.set(Array(finished), forKey: "finished"); recommendations.removeValue(forKey: row.pid)
    }
    func toggleFinished(_ row: Listener) {
        guard !busy && !protected(row) else { return }
        if finished.contains(row.intentKey) { finished.remove(row.intentKey) } else { finished.insert(row.intentKey) }
        defaults.set(Array(finished), forKey: "finished"); recommendations.removeValue(forKey: row.pid); selected.remove(row.pid)
        message = "Intent saved for this process lifetime and port set. Click Analyze to update Jev's recommendation; nothing was stopped."
    }
    private func pruneFinished() {
        finished.formIntersection(Set(rows.map(\.intentKey))); defaults.set(Array(finished), forKey: "finished")
    }
    var chosen: [Listener] { rows.filter { selected.contains($0.pid) && !protected($0) } }
    var portCount: Int { Set(rows.flatMap(\.ports)).count }
    func verdict(_ row: Listener) -> Decision? {
        if protected(row) { return .keep }
        if let result = interpretations[row.pid] { return result.verdict }
        if inspectionErrors[row.pid] != nil { return .uncertain }
        return nil
    }
    func verdictCount(_ decision: Decision) -> Int { rows.filter { verdict($0) == decision }.count }
    var candidateIDs: Set<Int32> { Set(rows.filter { !protected($0) && verdict($0) == .cleanup }.map(\.pid)) }
    func sortForTriage() {
        func rank(_ row: Listener) -> Int { switch verdict(row) { case .cleanup: return 0; case .uncertain: return 1; case .keep: return 2; case nil: return 3 } }
        rows.sort { (rank($0), $0.ports.first.flatMap(Int.init) ?? 0) < (rank($1), $1.ports.first.flatMap(Int.init) ?? 0) }
    }
    func evidenceSummary(_ row: Listener) -> String {
        guard let report = inspections[row.pid] else { return "" }
        if let ended = report.launchHistory.sessionEndedAt { return "Originating session closed \(Date(timeIntervalSince1970: ended).formatted(date: .omitted, time: .shortened)) · \(report.startup.profilePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? row.project)" }
        if let label = report.process.evidence?.launchdLabel { return "Service: \(label)" }
        if let module = report.startup.module { return "Module: \(module)" }
        return report.peers.isEmpty ? "No local client process identified in this snapshot" : "Clients: " + report.peers.map { "\($0.startup.module ?? $0.process.appName) (\($0.process.pid))" }.joined(separator: ", ")
    }
    func refresh() {
        guard !busy else { return }; inspections = [:]; interpretations = [:]; inspectionErrors = [:]
        busy = true; selected = []; recommendations = [:]; failure = nil; message = "Scanning TCP listeners…"
        Task {
            defer { busy = false }
            do { rows = try await Task.detached { try Scanner.scan() }.value; pruneFinished(); message = "Updated \(Date().formatted(date: .omitted, time: .shortened)). Select the processes you want to stop." }
            catch { rows = []; failure = error.localizedDescription; message = "Scan failed. Nothing was stopped." }
        }
    }
    func scanAllWithJev() {
        guard !busy else { return }; busy = true; failure = nil; selected = []; inspections = [:]; interpretations = [:]; inspectionErrors = [:]
        message = "Collecting rich evidence for every listening process…"
        Task {
            defer { busy = false }
            do {
                rows = try await Task.detached { try Scanner.scan() }.value
                let snapshot = rows
                requestedPIDs = snapshot.map(\.pid)
                for (index, row) in snapshot.enumerated() {
                    message = "Inspecting \(index + 1) of \(snapshot.count): \(row.appName), ports \(row.ports.joined(separator: ", "))…"
                    do { inspections[row.pid] = try await Inspection.collect(row) }
                    catch { inspectionErrors[row.pid] = error.localizedDescription }
                }
                message = "Jev is interpreting \(inspections.count) process dossiers in one request…"
                let batch = try await JevEvidence.interpretAll(snapshot.compactMap { inspections[$0.pid] }, protectedPIDs: Set(snapshot.filter { protected($0) }.map(\.pid)))
                let current = try await Task.detached { try Scanner.scan() }.value
                for row in snapshot {
                    guard let report = inspections[row.pid] else { continue }
                    if current.contains(where: { $0.intentKey == report.process.intentKey }) {
                        interpretations[row.pid] = batch.results[row.pid]
                        if let error = batch.errors[row.pid] { inspectionErrors[row.pid] = error }
                    } else { inspections.removeValue(forKey: row.pid); inspectionErrors[row.pid] = "Process changed or exited during analysis; result discarded." }
                }
                rows = current
                sortForTriage()
                message = "Scan complete: \(verdictCount(.cleanup)) kill recommended · \(verdictCount(.keep)) keep open · \(verdictCount(.uncertain)) your decision. Nothing selected or stopped."
            } catch { failure = error.localizedDescription; message = "Bulk interpretation unavailable. Collected evidence is still available through Inspect; nothing was stopped." }
        }
    }
    func stop(_ snapshot: [Listener]) {
        guard !busy else { return }; busy = true; failure = nil; message = "Rechecking identities and requesting graceful shutdown…"
        let protections = protections
        Task {
            defer { busy = false }
            do {
                let results = try await Task.detached { try Stopper.stop(snapshot, protections: protections) }.value
                let stamp = Date().formatted(date: .abbreviated, time: .standard)
                history = (results.map { "\(stamp) · \($0.name) · PID \($0.pid) · \($0.endpoints.joined(separator: ", "))\n\($0.status)" } + history).prefix(200).map { $0 }
                defaults.set(history, forKey: "history")
                let stopped = results.filter(\.stopped).count
                message = "\(stopped) of \(results.count) processes verified stopped. See History for every outcome."
                selected = []; recommendations = [:]
                inspections = [:]; interpretations = [:]; inspectionErrors = [:]
                rows = try await Task.detached { try Scanner.scan() }.value
            } catch { failure = error.localizedDescription; message = "Cleanup interrupted. Refresh before trying again."; selected = []; recommendations = [:] }
        }
    }
}

/// Explicit chrome treatment so standard controls stay readable in every
/// macOS appearance, including the borderless offscreen render preview.
private struct ChromeButtonStyle: ButtonStyle {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.isEnabled) private var isEnabled
    private var labelColor: Color { colorScheme == .dark ? .white : Color(white: 0.12) }
    private var fillColor: Color {
        colorScheme == .dark
            ? Color.primary.opacity(0.14)
            : Color.primary.opacity(0.08)
    }
    private var strokeColor: Color {
        colorScheme == .dark
            ? Color.primary.opacity(0.22)
            : Color.primary.opacity(0.14)
    }
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(isEnabled ? labelColor : labelColor.opacity(0.45))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(fillColor, in: RoundedRectangle(cornerRadius: 6))
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(strokeColor, lineWidth: 1)
            )
            .opacity(configuration.isPressed ? 0.82 : 1)
    }
}

struct PortView: View {
    @ObservedObject var model: PortModel
    @ViewState private var search = ""
    @ViewState private var category = "all"
    @ViewState private var showRules = false
    @ViewState private var showHistory = false
    @ViewState private var showConfirm = false
    @ViewState private var confirmation: [Listener] = []
    private var visible: [Listener] {
        return model.rows.filter { row in
            (category == "all" || model.verdict(row)?.rawValue == category) && (search.isEmpty || "\(row.appName) \(row.name) \(row.directory) \(row.pid) \(row.endpoints.joined(separator: " "))".localizedCaseInsensitiveContains(search))
        }
    }
    @ViewBuilder
    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Port Cleanup")
                        .font(.system(size: 28, weight: .semibold, design: .default))
                }
                Text("One scan. Kill recommended, keep open, or your decision—with the evidence.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 8) {
                HStack(spacing: 8) {
                    Button { showHistory = true } label: { Label("History", systemImage: "clock.arrow.circlepath") }
                    Button { showRules = true } label: { Label("Protections", systemImage: "shield") }
                        .disabled(model.busy)
                }.buttonStyle(ChromeButtonStyle()).controlSize(.regular)
                HStack(spacing: 14) {
                    if model.busy { ProgressView().controlSize(.small) }
                    Button { model.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                        .disabled(model.busy)
                        .keyboardShortcut("r", modifiers: .command)
                    Button { model.scanAllWithJev() } label: { Label("Scan all with Jev", systemImage: "sparkles") }
                        .disabled(model.busy)
                        .buttonStyle(.borderedProminent)
                        .tint(.green)
                }
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 22)
        .padding(.bottom, 18)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            HStack(spacing: 14) {
                Picker("Verdict filter", selection: $category) {
                    Text("All processes (\(model.rows.count))").tag("all")
                    Text("Kill recommended (\(model.verdictCount(.cleanup)))").tag(Decision.cleanup.rawValue)
                    Text("Keep open (\(model.verdictCount(.keep)))").tag(Decision.keep.rawValue)
                    Text("Your decision (\(model.verdictCount(.uncertain)))").tag(Decision.uncertain.rawValue)
                }
                .pickerStyle(.segmented)
                .fixedSize()
                .accessibilityIdentifier("verdict-filter")
                Spacer()
                Button { model.selected = model.candidateIDs } label: {
                    Label("Select kill recommendations", systemImage: "checkmark.circle")
                }.disabled(model.busy || model.candidateIDs.isEmpty)
            }
            .buttonStyle(ChromeButtonStyle())
            .controlSize(.regular)
            .padding(.horizontal, 20)
            .padding(.top, 12)
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Find a port, app, process, or project", text: $search)
                    .textFieldStyle(.plain)
                    .accessibilityIdentifier("search-field")
                Spacer()
                Button("Clear selection") { model.selected = [] }.disabled(model.busy || model.selected.isEmpty).buttonStyle(ChromeButtonStyle())
                killSelectedButton("top")
            }.padding(.horizontal, 20).padding(.vertical, 12)
            HStack {
                Text("Select / process").frame(width: 205, alignment: .leading)
                Text("Ports & project").frame(maxWidth: .infinity, alignment: .leading)
                Text("Jev recommendation & why").frame(width: 355, alignment: .leading)
                Text("Keep").frame(width: 60)
            }
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 22)
            .padding(.vertical, 9)
            .background(.quaternary.opacity(0.35))
            ScrollView {
                LazyVStack(spacing: 0) {
                    if visible.isEmpty {
                        VStack(spacing: 14) {
                            Image(systemName: model.busy ? "network" : model.rows.isEmpty ? "checkmark.circle" : "magnifyingglass")
                                .font(.system(size: 38, weight: .light))
                                .foregroundStyle(model.busy ? Color.secondary : model.rows.isEmpty ? Color.green : Color.secondary)
                            Text(model.busy ? "Scanning TCP listeners…" : model.rows.isEmpty ? "No TCP listeners right now." : "No processes match this filter or search.")
                                .font(.headline)
                            Text(model.busy ? "This collects current listening sockets and process identity. Nothing is stopped." :
                                 model.rows.isEmpty ? "Nothing is listening. Refresh later to check again." : "Try a broader search or a different verdict filter.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(60)
                    }
                    ForEach(visible) { row in
                        PortRow(row: row, model: model)
                        Divider().padding(.horizontal, 20)
                    }
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 5) {
                        if let failure = model.failure {
                            Label(failure, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                                .textSelection(.enabled)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            Label(model.message, systemImage: model.busy ? "hourglass" : "checkmark.circle")
                                .font(.callout)
                                .foregroundStyle(model.busy ? .secondary : .primary)
                                .lineLimit(2)
                        }
                        Text("Stopping a process closes all its ports and may interrupt its app or unsaved work. TCP only; no administrator access.")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }
                    .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
                    killSelectedButton("footer").layoutPriority(1)
                }
            }.padding(20)
        }.frame(minWidth: 1120, minHeight: 700)
        .sheet(isPresented: $showRules) { rulesSheet }
        .sheet(isPresented: $showHistory) { historySheet }
        .sheet(isPresented: $showConfirm) { confirmationSheet }
        .sheet(item: $model.inspectionTarget) { row in
            let cached = model.inspections[row.pid].flatMap { $0.process.intentKey == row.intentKey ? $0 : nil }
            InspectorView(row: row, model: model, initialReport: cached, initialInterpretation: cached == nil ? nil : model.interpretations[row.pid])
        }
    }
    private func killSelectedButton(_ location: String) -> some View {
        Button {
            guard !model.busy && !model.chosen.isEmpty else { return }
            confirmation = model.chosen
            showConfirm = true
        } label: {
            Label("Stop selected (\(model.chosen.count))", systemImage: "stop.circle.fill")
                .font(.system(size: 14, weight: .semibold)).lineLimit(1)
                .foregroundStyle(.white).padding(.horizontal, 16).padding(.vertical, 10)
                .background(model.busy || model.chosen.isEmpty ? Color.gray.opacity(0.4) : Color.red, in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .fixedSize(horizontal: true, vertical: false)
        .disabled(model.busy || model.chosen.isEmpty)
        .accessibilityIdentifier("kill-selected-\(location)")
        .help("Review all selected processes, then confirm their shutdown")
        .accessibilityLabel("Stop selected processes (\(model.chosen.count)). Opens confirmation before any shutdown.")
    }

    private var rulesSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Your protected processes", systemImage: "shield.fill").font(.title2.bold()).foregroundStyle(.green)
            Text("Jev recommends Stop, Keep open or Your decision using the full inspection. Your shields always override the model and block shutdown. A familiar product name alone is not a keep rule.")
            Text("Privacy & cost").font(.headline)
            Text("Inspect is local and free. It reads a safe subset of startup arguments, identifies connected processes, and reads target metadata only from a verified loopback headless-browser debugging port. It does not navigate pages or probe arbitrary HTTP services. Optional Jev interpretation receives minimized startup, peer and workload evidence; full paths, raw commands, remote page details and secrets are withheld. One paid request per explicit click.").font(.callout).foregroundStyle(.secondary)
            Text("Remembered shields (\(model.protections.count))").font(.headline)
            ScrollView { VStack(alignment: .leading, spacing: 8) {
                ForEach(model.protections.sorted(), id: \.self) { key in
                    HStack { Text(key.replacingOccurrences(of: "\u{1f}", with: " · ")).font(.caption).textSelection(.enabled); Spacer(); Button("Remove") { model.protections.remove(key); UserDefaults.standard.set(Array(model.protections), forKey: "protections") } }
                }
            } }.frame(maxHeight: 100)
            Text("Shields remember the executable, project folder, and exact port set. A changed project or port set needs a new shield.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Done") { showRules = false }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent) }
        }.padding(24).frame(width: 630)
    }
    private var historySheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Cleanup history", systemImage: "clock.arrow.circlepath").font(.title2.bold())
            Text("Last 200 outcomes, stored only on this Mac.").foregroundStyle(.secondary)
            ScrollView { VStack(alignment: .leading, spacing: 16) {
                if model.history.isEmpty { Text("Nothing has been stopped by this app.").foregroundStyle(.secondary) }
                ForEach(Array(model.history.enumerated()), id: \.offset) { _, line in Text(line).font(.callout).textSelection(.enabled); Divider() }
            }.frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 400)
            HStack { Spacer(); Button("Done") { showHistory = false }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent) }
        }.padding(24).frame(width: 650)
    }
    private var confirmationSheet: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Stop \(confirmation.count) selected processes?", systemImage: "exclamationmark.triangle.fill").font(.title2.bold()).foregroundStyle(.orange)
            Text("This stops the entire process, not just one port. It may close an app, interrupt an agent session, or discard unsaved work. Your selection includes every item below, even if hidden by search.")
            ScrollView { VStack(alignment: .leading, spacing: 14) {
                ForEach(confirmation) { row in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(row.appName) · PID \(row.pid)").bold()
                        Text("All listeners: \(row.endpoints.joined(separator: ", "))")
                        Text(row.directory).font(.caption).foregroundStyle(.secondary)
                        if row.connections > 0 { Text("\(row.connections) established connections on this process").foregroundStyle(.orange) }

                    }; Divider()
                }
            } }.frame(maxHeight: 300)
            Text("The app checks each process identity and port set again before sending a graceful stop. Changed or protected processes are skipped. It never force-kills or disables restart services.").font(.callout).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Cancel") { showConfirm = false }.keyboardShortcut(.cancelAction); Button("Confirm stop selected processes", role: .destructive) { showConfirm = false; model.stop(confirmation) }.buttonStyle(.borderedProminent).tint(.red) }
        }.padding(26).frame(width: 660)
    }
}

struct PortRow: View {
    let row: Listener
    @ObservedObject var model: PortModel

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            HStack(spacing: 10) {
                Toggle("Select \(row.appName)", isOn: Binding(get: { model.selected.contains(row.pid) }, set: { if $0 { model.selected.insert(row.pid) } else { model.selected.remove(row.pid) } })).labelsHidden().toggleStyle(.checkbox).disabled(model.busy || model.protected(row))
                VStack(alignment: .leading, spacing: 4) {
                    Text(row.appName).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                    Text("PID \(row.pid)").font(.caption).foregroundStyle(.secondary)
                }
            }.frame(width: 193, alignment: .leading)
            VStack(alignment: .leading, spacing: 5) {
                Text(row.ports.joined(separator: ", ")).font(.system(size: 13, weight: .medium, design: .monospaced))
                Text("\(row.project) · \(row.evidence?.establishedScanStatus == "available" ? "\(row.evidence?.inboundCount ?? 0) listener clients" : "activity unavailable")").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !model.evidenceSummary(row).isEmpty { Text(model.evidenceSummary(row)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
            }.frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 4) {
                if model.protected(row) {
                    HStack(spacing: 6) {
                        Image(systemName: "shield.fill").foregroundStyle(.green)
                        Text("Keep open · protected").font(.system(size: 12, weight: .semibold)).foregroundStyle(.green)
                    }
                } else if let interpretation = model.interpretations[row.pid] {
                    HStack(spacing: 6) {
                        Image(systemName: interpretation.verdict == .cleanup ? "exclamationmark.octagon.fill" : interpretation.verdict == .keep ? "checkmark.circle.fill" : "questionmark.circle.fill")
                            .foregroundStyle(interpretation.verdict == .cleanup ? .red : interpretation.verdict == .keep ? .green : .orange)
                        Text(interpretation.label).font(.system(size: 13, weight: .bold)).foregroundStyle(interpretation.verdict == .cleanup ? .red : interpretation.verdict == .keep ? .green : .orange)
                    }
                    Text(interpretation.reason).font(.caption).fixedSize(horizontal: false, vertical: true)
                    if interpretation.verdict == .uncertain { Text(interpretation.missingFact).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                } else if let error = model.inspectionErrors[row.pid] {
                    Text("Your decision · inspection unavailable").foregroundStyle(.orange)
                    Text(error).font(.caption).foregroundStyle(.secondary)
                } else { Text(model.inspections[row.pid] == nil ? "Not scanned with Jev" : "Evidence collected; awaiting Jev").font(.caption).foregroundStyle(.secondary) }
                Button("Evidence & process details…") { model.inspectionTarget = row }.disabled(model.busy).buttonStyle(ChromeButtonStyle()).controlSize(.small)
                Text("Started \(Date(timeIntervalSince1970: Double(row.start) / 1_000_000).formatted(date: .abbreviated, time: .shortened))").font(.caption).foregroundStyle(.secondary)
            }.font(.system(size: 12, weight: .medium)).frame(width: 343, alignment: .leading)
            Button { model.toggleProtection(row) } label: { Image(systemName: model.protected(row) ? "shield.fill" : "shield").foregroundStyle(model.protected(row) ? .green : .secondary) }.buttonStyle(.borderless).frame(width: 60).disabled(model.busy || row.hardProtection != nil).help(row.hardProtection ?? "Remember this executable + project + port set as protected")
        }.padding(.horizontal, 22).padding(.vertical, 14)
        .background(model.selected.contains(row.pid) ? Color.orange.opacity(0.07) : Color.clear)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(row.appName), PID \(row.pid), ports \(row.ports.joined(separator: ", ")), project \(row.project)")

    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

struct CleanupApplication: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = PortModel()
    var body: some Scene {
        Window("Port Cleanup", id: "main") { PortView(model: model).task { model.refresh() } }.defaultSize(width: 1280, height: 820)
    }
}

struct AnalysisAudit: Codable {
    let rows: [Listener]
    let recommendations: [String: Recommendation]
}
struct BulkAudit: Codable {
    let requestedPIDs: [Int32]; let reports: [Int32: InspectionReport]; let interpretations: [Int32: EvidenceInterpretation]; let errors: [Int32: String]; let failure: String?; let message: String; let selectedCount: Int
}

@main struct Launcher {
    @MainActor static func main() async {
        do {
            let args = CommandLine.arguments
            if args.contains("--verify-jev-connection") { _ = try Credential.read(); print("TypeSafe Keychain access verified; no API request made."); return }
            if args.contains("--connect-jev-from-environment") { try Credential.installFromEnvironment(); print("TypeSafe connected in Keychain; read-back verified."); return }
            if args.contains("--scan") { print(String(decoding: try JSONEncoder().encode(Scanner.scan()), as: UTF8.self)); return }
            if args.contains("--verify-bulk-scan-once") {
                let model = PortModel(); model.scanAllWithJev()
                while model.busy { try await Task.sleep(nanoseconds: 100_000_000) }
                print(String(decoding: try JSONEncoder().encode(BulkAudit(requestedPIDs: model.requestedPIDs, reports: model.inspections, interpretations: model.interpretations, errors: model.inspectionErrors, failure: model.failure, message: model.message, selectedCount: model.selected.count)), as: UTF8.self)); return
            }
            if let index = args.firstIndex(of: "--inspect-port"), args.count > index + 1 {
                let port = args[index + 1]
                let matches = try Scanner.scan().filter { $0.ports.contains(port) }
                guard matches.count == 1, let row = matches.first else { throw PortError("Expected exactly one listener owner for port \(port); found \(matches.count)") }
                let report = try await Inspection.collect(row)
                if let imageIndex = args.firstIndex(of: "--render-inspector"), args.count > imageIndex + 1 {
                    NSApplication.shared.setActivationPolicy(.prohibited)
                    let model = PortModel(); model.rows = [row]
                    let host = NSHostingView(rootView: InspectorView(row: row, model: model, initialReport: report))
                    host.frame = NSRect(x: 0, y: 0, width: 860, height: 800)
                    let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 860, height: 800), styleMask: .borderless, backing: .buffered, defer: false)
                    window.contentView = host; host.layoutSubtreeIfNeeded(); window.display()
                    guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw PortError("Could not render inspector") }
                    host.cacheDisplay(in: host.bounds, to: bitmap)
                    guard let png = bitmap.representation(using: .png, properties: [:]) else { throw PortError("Could not encode inspector preview") }
                    try png.write(to: URL(fileURLWithPath: args[imageIndex + 1])); print("Rendered inspector from real port \(port) evidence; no AI call made."); return
                }
                if args.contains("--interpret-once") {
                    let interpretation = try await JevEvidence.interpret(report)
                    struct Audit: Encodable { let report: InspectionReport; let interpretation: EvidenceInterpretation }
                    print(String(decoding: try JSONEncoder().encode(Audit(report: report, interpretation: interpretation)), as: UTF8.self))
                } else { print(String(decoding: try JSONEncoder().encode(report), as: UTF8.self)) }
                return
            }
            if args.contains("--analyze-once") || args.contains("--analyze-audit-once") {
                let rows = try Scanner.scan().filter { $0.hardProtection == nil }
                let result = try await Jev.analyze(rows: rows, rules: Jev.defaultRules)
                if args.contains("--analyze-audit-once") {
                    let audit = AnalysisAudit(rows: rows, recommendations: Dictionary(uniqueKeysWithValues: result.map { (String($0.key), $0.value) }))
                    print(String(decoding: try JSONEncoder().encode(audit), as: UTF8.self))
                } else { print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self)) }
                return
            }
            if let index = args.firstIndex(of: "--render-preview"), args.count > index + 1 {
                NSApplication.shared.setActivationPolicy(.prohibited)
                let model = PortModel(); model.rows = try Scanner.scan()
                if let auditIndex = args.firstIndex(of: "--bulk-audit"), args.count > auditIndex + 1 {
                    let audit = try JSONDecoder().decode(BulkAudit.self, from: Data(contentsOf: URL(fileURLWithPath: args[auditIndex + 1])))
                    for row in model.rows {
                        if let report = audit.reports[row.pid], report.process.intentKey == row.intentKey {
                            model.inspections[row.pid] = report; model.interpretations[row.pid] = audit.interpretations[row.pid]; model.inspectionErrors[row.pid] = audit.errors[row.pid]
                        }
                    }
                    model.message = "Verified bulk results: \(model.verdictCount(.cleanup)) kill recommended · \(model.verdictCount(.keep)) keep open · \(model.verdictCount(.uncertain)) your decision. Nothing selected or stopped."
                    model.sortForTriage()
                }
                if let auditIndex = args.firstIndex(of: "--analysis-audit"), args.count > auditIndex + 1 {
                    let audit = try JSONDecoder().decode(AnalysisAudit.self, from: Data(contentsOf: URL(fileURLWithPath: args[auditIndex + 1])))
                    for row in model.rows where audit.rows.contains(where: { $0.intentKey == row.intentKey }) { model.recommendations[row.pid] = audit.recommendations[String(row.pid)] }
                    model.message = "Verified Jev results from the saved audit; no new AI request was made for this preview."
                }
                if args.contains("--preview-selection") {
                    model.selected = Set(model.rows.filter { !model.protected($0) }.prefix(2).map(\.pid))
                    model.message = "Read-only selected-state preview: no process has been signalled."
                }
                let size = NSSize(width: args.contains("--compact-preview") ? 1120 : 1280, height: args.contains("--compact-preview") ? 700 : 900)
                let host = NSHostingView(rootView: PortView(model: model))
                host.frame = NSRect(origin: .zero, size: size)
                let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: size.width, height: size.height), styleMask: .borderless, backing: .buffered, defer: false)
                window.contentView = host; host.layoutSubtreeIfNeeded(); window.display()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw PortError("Could not allocate UI preview") }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { throw PortError("Could not render UI preview") }
                try png.write(to: URL(fileURLWithPath: args[index + 1]))
                print("Rendered native UI with \(model.rows.count) real processes / \(model.portCount) ports."); return
            }
            NSApplication.shared.setActivationPolicy(.regular)
            CleanupApplication.main()
        } catch { fputs("\(error.localizedDescription)\n", stderr); exit(1) }
    }
}
