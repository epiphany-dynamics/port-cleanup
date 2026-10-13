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
        message = "Intent saved for this process lifetime and port set. Click Scan all with Jev or Interpret to update recommendation; nothing was stopped."
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
/// macOS appearance and active theme preset.
struct ChromeButtonStyle: ButtonStyle {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.isEnabled) private var isEnabled
    @ObservedObject private var appearance = AppearanceSettings.shared

    private var labelColor: Color {
        MissionTheme.primaryText(colorScheme)
    }
    private var fillColor: Color {
        MissionTheme.cardFill(colorScheme, elevated: true)
    }
    private var strokeColor: Color {
        MissionTheme.cardStroke(colorScheme)
    }
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12.5, weight: .semibold, design: .rounded))
            .foregroundStyle(isEnabled ? labelColor : labelColor.opacity(0.42))
            .padding(.horizontal, 12)
            .padding(.vertical, 6.5)
            .background(fillColor, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(strokeColor, lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(.spring(response: 0.2, dampingFraction: 0.75), value: configuration.isPressed)
    }
}

struct PortView: View {
    @ObservedObject var model: PortModel
    @ObservedObject private var appearance = AppearanceSettings.shared
    @Environment(\.colorScheme) private var colorScheme
    @ViewState private var search = ""
    @ViewState private var category = "all"
    @ViewState private var showRules = false
    @ViewState private var showConnection = false
    @ViewState private var showAppearance = false
    @ViewState private var keySaved = TypeSafeKeyStore().isSaved
    @ViewState private var showHistory = false
    @ViewState private var showConfirm = false
    @ViewState private var confirmation: [Listener] = []
    @ViewState private var expandedPIDs: Set<Int32> = []
    @ViewState private var copiedToast: String? = nil

    private var visible: [Listener] {
        return model.rows.filter { row in
            (category == "all" || model.verdict(row)?.rawValue == category) &&
            (search.isEmpty || "\(row.appName) \(row.name) \(row.directory) \(row.pid) \(row.endpoints.joined(separator: " "))".localizedCaseInsensitiveContains(search))
        }
    }

    private func showCopyToast(_ text: String) {
        withAnimation(.spring(response: 0.28, dampingFraction: 0.75)) {
            copiedToast = text
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
            withAnimation(.easeOut(duration: 0.2)) {
                if copiedToast == text { copiedToast = nil }
            }
        }
    }

    private func ask(_ agent: LocalAgent) {
        let snapshots = model.rows.map { row in
            let status: String
            if let hard = row.hardProtection {
                status = "Protected: \(hard)"
            } else if model.protected(row) {
                status = "Protected"
            } else if let result = model.interpretations[row.pid] {
                let verdict = result.verdict == .cleanup ? "Stop" : result.verdict == .keep ? "Keep open" : "Your decision"
                status = "\(verdict). \(result.label). \(result.reason)"
            } else if model.inspectionErrors[row.pid] != nil {
                status = "Evidence could not be collected"
            } else {
                status = "Not analyzed yet"
            }
            return AskFacts.snapshot(row, status: status, detail: model.evidenceSummary(row), selected: model.selected.contains(row.pid))
        }
        do {
            let command = try AgentLaunch.prepare(agent: agent, brief: AskBrief.text(rows: snapshots))
            AgentLaunch.open(command)
            model.failure = nil
            model.message = AgentLaunch.openedMessage(agent)
        } catch {
            model.failure = (error as? LocalizedError)?.errorDescription ?? "Could not open \(agent.title). Nothing was stopped."
            model.message = "Ask failed. Nothing was stopped."
        }
    }

    @ViewBuilder
    private var header: some View {
        HStack(alignment: .center, spacing: 18) {
            RadarOrb(
                busy: model.busy,
                cleanupCount: model.verdictCount(.cleanup),
                uncertainCount: model.verdictCount(.uncertain),
                size: 52
            )

            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .center, spacing: 10) {
                    Text("Port Cleanup")
                        .font(.system(size: 27, weight: .bold, design: .rounded))
                    HStack(spacing: 5) {
                        Circle()
                            .fill(model.busy ? MissionTheme.teal : MissionTheme.emerald)
                            .frame(width: 6, height: 6)
                        Text(model.busy ? "SCANNING" : "\(model.rows.count) LISTENERS · \(model.portCount) PORTS")
                            .font(.system(size: 10, weight: .heavy, design: .monospaced))
                            .foregroundStyle(model.busy ? MissionTheme.teal : .secondary)
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 4)
                    .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                    .overlay(Capsule().stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))
                }
                Text("One scan. Kill recommended, keep open, or your decision—with local process evidence on screen.")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 10) {
                HStack(spacing: 8) {
                    Button { showAppearance = true } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "paintbrush.pointed.fill")
                                .foregroundStyle(MissionTheme.teal)
                            Text("Appearance")
                        }
                    }
                    .help("Customize theme palette and light/dark appearance (⌘,)")

                    Menu {
                        Button("Claude Code") { ask(.claudeCode) }
                        Button("Codex") { ask(.codex) }
                        Button("Hermes") { ask(.hermes) }
                    } label: {
                        Label("Ask Agent", systemImage: "bubble.left.and.bubble.right.fill")
                    }
                    .help("Ask Claude Code, Codex, or Hermes about this scan. Nothing is stopped.")
                    .buttonStyle(ChromeButtonStyle())
                    .disabled(model.busy || model.rows.isEmpty)

                    Button { showHistory = true } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "clock.arrow.circlepath")
                            Text("History")
                            if !model.history.isEmpty {
                                Text("\(model.history.count)")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundStyle(MissionTheme.teal)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(MissionTheme.teal.opacity(0.15), in: Capsule())
                            }
                        }
                    }

                    Button { showConnection = true } label: {
                        HStack(spacing: 5) {
                            Image(systemName: keySaved ? "checkmark.key.fill" : "key.fill")
                                .foregroundStyle(keySaved ? MissionTheme.emerald : MissionTheme.amber)
                            Text(keySaved ? "TypeSafe key saved" : "Connect TypeSafe")
                        }
                    }
                    .disabled(model.busy)
                    .accessibilityIdentifier("typesafe-connect")

                    Button { showRules = true } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "shield.lefthalf.filled")
                                .foregroundStyle(MissionTheme.emerald)
                            Text("Protections")
                            if !model.protections.isEmpty {
                                Text("\(model.protections.count)")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundStyle(MissionTheme.emerald)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(MissionTheme.emerald.opacity(0.15), in: Capsule())
                            }
                        }
                    }
                    .disabled(model.busy)
                }
                .buttonStyle(ChromeButtonStyle())
                .controlSize(.regular)

                HStack(spacing: 10) {
                    if let toast = copiedToast {
                        HStack(spacing: 5) {
                            Image(systemName: "doc.on.clipboard.fill")
                                .foregroundStyle(MissionTheme.emerald)
                            Text(toast)
                                .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(MissionTheme.emerald.opacity(0.16), in: Capsule())
                        .overlay(Capsule().stroke(MissionTheme.emerald.opacity(0.4), lineWidth: 1))
                        .transition(.opacity.combined(with: .scale(scale: 0.92)))
                    }

                    if model.busy {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Scanning…")
                                .font(.system(size: 11.5, weight: .medium, design: .rounded))
                                .foregroundStyle(.secondary)
                        }
                    }

                    Button { model.refresh() } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(ChromeButtonStyle())
                    .disabled(model.busy)
                    .keyboardShortcut("r", modifiers: .command)

                    Button {
                        keySaved = TypeSafeKeyStore().isSaved
                        if keySaved { model.scanAllWithJev() } else { showConnection = true }
                    } label: {
                        Label("Scan all with Jev", systemImage: "sparkles")
                    }
                    .disabled(model.busy)
                    .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                }
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }

    @ViewBuilder
    private var telemetryDeck: some View {
        HStack(spacing: 12) {
            TelemetryStatCard(
                title: "ALL LISTENERS",
                subtitle: "\(model.portCount) open TCP ports",
                count: model.rows.count,
                icon: "dot.radiowaves.left.and.right",
                tint: MissionTheme.teal,
                isActive: category == "all",
                onSelect: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) { category = "all" }
                }
            )

            TelemetryStatCard(
                title: "KILL RECOMMENDED",
                subtitle: model.candidateIDs.isEmpty ? "No stale tasks flagged" : "Ready for review",
                count: model.verdictCount(.cleanup),
                icon: "scope",
                tint: MissionTheme.coral,
                isActive: category == Decision.cleanup.rawValue,
                actionLabel: model.candidateIDs.isEmpty ? nil : (model.selected == model.candidateIDs ? "Selected" : "Select all"),
                onAction: {
                    guard !model.busy && !model.candidateIDs.isEmpty else { return }
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                        model.selected = model.candidateIDs
                    }
                },
                onSelect: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) { category = Decision.cleanup.rawValue }
                }
            )

            TelemetryStatCard(
                title: "YOUR DECISION",
                subtitle: "Needs human judgment",
                count: model.verdictCount(.uncertain),
                icon: "questionmark.diamond.fill",
                tint: MissionTheme.amber,
                isActive: category == Decision.uncertain.rawValue,
                onSelect: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) { category = Decision.uncertain.rawValue }
                }
            )

            TelemetryStatCard(
                title: "KEEP OPEN",
                subtitle: "\(model.protections.count) remembered shields",
                count: model.verdictCount(.keep),
                icon: "shield.checkered",
                tint: MissionTheme.emerald,
                isActive: category == Decision.keep.rawValue,
                onSelect: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) { category = Decision.keep.rawValue }
                }
            )
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }

    @ViewBuilder
    private var commandBar: some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
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

                Button {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                        model.selected = model.candidateIDs
                    }
                } label: {
                    Label("Select kill recommendations", systemImage: "checkmark.circle.fill")
                }
                .buttonStyle(ChromeButtonStyle())
                .disabled(model.busy || model.candidateIDs.isEmpty)

                Button {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                        if expandedPIDs.count == visible.count {
                            expandedPIDs.removeAll()
                        } else {
                            expandedPIDs = Set(visible.map(\.pid))
                        }
                    }
                } label: {
                    Label(
                        expandedPIDs.count == visible.count && !visible.isEmpty ? "Collapse details" : "Expand details",
                        systemImage: expandedPIDs.count == visible.count && !visible.isEmpty ? "rectangle.compress.vertical" : "rectangle.expand.vertical"
                    )
                }
                .buttonStyle(ChromeButtonStyle())
                .disabled(visible.isEmpty)
            }

            HStack(spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(MissionTheme.teal)
                    TextField("Find a port, app, process, PID, or project folder…", text: $search)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13, weight: .medium))
                        .accessibilityIdentifier("search-field")
                    if !search.isEmpty {
                        Button {
                            search = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(MissionTheme.cardFill(colorScheme, elevated: true))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1)
                )

                Button("Clear selection") {
                    withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                        model.selected = []
                    }
                }
                .disabled(model.busy || model.selected.isEmpty)
                .buttonStyle(ChromeButtonStyle())

                killSelectedButton("top")
            }
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }

    var body: some View {
        ZStack {
            MissionControlBackdrop()

            VStack(alignment: .leading, spacing: 0) {
                header
                telemetryDeck
                commandBar

                Divider().opacity(0.4)

                ScrollView {
                    LazyVStack(spacing: 10) {
                        if visible.isEmpty {
                            emptyRadarState
                        } else {
                            ForEach(visible) { row in
                                PortRow(
                                    row: row,
                                    model: model,
                                    isExpanded: expandedPIDs.contains(row.pid),
                                    onToggleExpand: {
                                        withAnimation(.spring(response: 0.32, dampingFraction: 0.78)) {
                                            if expandedPIDs.contains(row.pid) {
                                                expandedPIDs.remove(row.pid)
                                            } else {
                                                expandedPIDs.insert(row.pid)
                                            }
                                        }
                                    },
                                    onCopyToast: { text in
                                        showCopyToast(text)
                                    }
                                )
                            }
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.vertical, 14)
                }

                Divider().opacity(0.4)

                footerBar
            }
        }
        .frame(minWidth: 1120, minHeight: 700)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
        .sheet(isPresented: $showAppearance) {
            AppearanceSettingsView(isModalSheet: true)
        }
        .sheet(isPresented: $showRules) { rulesSheet }
        .sheet(isPresented: $showConnection, onDismiss: { keySaved = TypeSafeKeyStore().isSaved }) {
            TypeSafeConnectionView {
                keySaved = true; model.failure = nil
                model.message = "TypeSafe key saved in Keychain. Click Scan all with Jev when ready; no API request was made."
            }
        }
        .sheet(isPresented: $showHistory) { historySheet }
        .sheet(isPresented: $showConfirm) { confirmationSheet }
        .sheet(item: $model.inspectionTarget, onDismiss: { keySaved = TypeSafeKeyStore().isSaved }) { row in
            let cached = model.inspections[row.pid].flatMap { $0.process.intentKey == row.intentKey ? $0 : nil }
            InspectorView(row: row, model: model, initialReport: cached, initialInterpretation: cached == nil ? nil : model.interpretations[row.pid])
        }
    }

    @ViewBuilder
    private var emptyRadarState: some View {
        VStack(spacing: 16) {
            RadarOrb(
                busy: model.busy,
                cleanupCount: 0,
                uncertainCount: 0,
                size: 76
            )
            Text(
                model.busy
                    ? "Scanning TCP listeners across your Mac…"
                    : model.rows.isEmpty
                        ? "All Clear — No TCP Listeners Active"
                        : "No Processes Match Your Active Filter"
            )
            .font(.system(size: 18, weight: .bold, design: .rounded))

            Text(
                model.busy
                    ? "Collecting listening sockets, process identities, and local connection evidence. Nothing is stopped."
                    : model.rows.isEmpty
                        ? "No user or local TCP ports are open right now. Click Refresh anytime to sweep again."
                        : "Try clearing your search query or switching to 'All processes' above."
            )
            .font(.system(size: 13.5))
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 460)

            if !model.busy && (!search.isEmpty || category != "all") {
                Button {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) {
                        search = ""
                        category = "all"
                    }
                } label: {
                    Label("Reset filters", systemImage: "arrow.counterclockwise")
                }
                .buttonStyle(ChromeButtonStyle())
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 56)
        .padding(.horizontal, 24)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(MissionTheme.cardFill(colorScheme))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1)
        )
    }

    @ViewBuilder
    private var footerBar: some View {
        HStack(spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill((model.failure != nil ? MissionTheme.amber : (model.busy ? MissionTheme.teal : MissionTheme.emerald)).opacity(0.16))
                        .frame(width: 34, height: 34)
                    Image(systemName: model.failure != nil ? "exclamationmark.triangle.fill" : (model.busy ? "antenna.radiowaves.left.and.right" : "checkmark.shield.fill"))
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(model.failure != nil ? MissionTheme.amber : (model.busy ? MissionTheme.teal : MissionTheme.emerald))
                }

                VStack(alignment: .leading, spacing: 3) {
                    if let failure = model.failure {
                        Text(failure)
                            .foregroundStyle(MissionTheme.amber)
                            .textSelection(.enabled)
                            .font(.system(size: 13, weight: .semibold))
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text(model.message)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(model.busy ? .secondary : .primary)
                            .lineLimit(2)
                    }
                    Text("Stopping a process closes all its listening ports and sends graceful SIGTERM after re-verifying PID, start time, and shield status. TCP only.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)

            if !model.chosen.isEmpty {
                HStack(spacing: 6) {
                    Text("\(model.chosen.count) queued")
                        .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                        .foregroundStyle(MissionTheme.coral)
                    Text("· \(Set(model.chosen.flatMap(\.ports)).count) ports")
                        .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(MissionTheme.coral.opacity(0.12), in: Capsule())
                .overlay(Capsule().stroke(MissionTheme.coral.opacity(0.35), lineWidth: 1))
            }

            killSelectedButton("footer").layoutPriority(1)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 14)
        .background(MissionTheme.cardFill(colorScheme, elevated: true))
    }

    private func killSelectedButton(_ location: String) -> some View {
        let disabled = model.busy || model.chosen.isEmpty
        return Button {
            guard !disabled else { return }
            confirmation = model.chosen
            showConfirm = true
        } label: {
            HStack(spacing: 7) {
                Image(systemName: "stop.circle.fill")
                    .font(.system(size: 14, weight: .bold))
                Text("Stop selected (\(model.chosen.count))")
                    .font(.system(size: 13.5, weight: .bold, design: .rounded))
                    .lineLimit(1)
            }
            .foregroundStyle(disabled ? Color.secondary : Color.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(
                        disabled
                            ? LinearGradient(colors: [MissionTheme.disabledFill(colorScheme), MissionTheme.disabledFill(colorScheme)], startPoint: .top, endPoint: .bottom)
                            : LinearGradient(colors: [MissionTheme.coral, MissionTheme.coral.opacity(0.82)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(disabled ? MissionTheme.cardStroke(colorScheme) : Color.white.opacity(0.28), lineWidth: 1)
            )
            .shadow(color: disabled ? .clear : MissionTheme.coral.opacity(0.35), radius: 7, y: 2)
        }
        .buttonStyle(.plain)
        .fixedSize(horizontal: true, vertical: false)
        .disabled(disabled)
        .accessibilityIdentifier("kill-selected-\(location)")
        .help("Review all selected processes, then confirm their shutdown")
        .accessibilityLabel("Stop selected processes (\(model.chosen.count)). Opens confirmation before any shutdown.")
    }

    // MARK: - Secondary Sheets (Protections, History, Confirmation)

    private func parseProtectionKey(_ key: String) -> (executable: String, directory: String, ports: [String]) {
        let parts = key.components(separatedBy: "\u{1f}")
        let exe = parts.indices.contains(0) ? parts[0] : key
        let dir = parts.indices.contains(1) ? parts[1] : ""
        let ports = parts.indices.contains(2) ? parts[2].split(separator: ",").map(String.init) : []
        return (exe, dir, ports)
    }

    private var rulesSheet: some View {
        ZStack {
            MissionControlBackdrop()
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(MissionTheme.emerald.opacity(0.18))
                            .frame(width: 44, height: 44)
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundStyle(MissionTheme.emerald)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Protected Processes & Privacy Model")
                            .font(.system(size: 21, weight: .bold, design: .rounded))
                        Text("Your shields always override Jev and block shutdown. A familiar product name alone is never a keep rule.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                VStack(alignment: .leading, spacing: 8) {
                    Label("Local Evidence First · Strict Privacy Guardrails", systemImage: "lock.laptopcomputer")
                        .font(.system(size: 13.5, weight: .bold, design: .rounded))
                        .foregroundStyle(MissionTheme.teal)
                    Text("Inspect is 100% local and free. It reads an allowlisted subset of startup arguments, identifies connected peer processes, and reads target metadata only from a verified loopback headless-browser debugging port without navigating pages or probing arbitrary HTTP services.")
                        .font(.system(size: 12.5))
                        .foregroundStyle(.secondary)
                    Text("Optional Jev interpretation sends minimized startup, peer, and workload evidence in a single explicit request per click. Full paths, raw command lines, remote page details, and secrets never leave this Mac.")
                        .font(.system(size: 12.5))
                        .foregroundStyle(.secondary)
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(MissionTheme.cardFill(colorScheme, elevated: true)))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme, accent: MissionTheme.teal), lineWidth: 1))

                HStack {
                    Label("Remembered Shields (\(model.protections.count))", systemImage: "shield.fill")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(MissionTheme.emerald)
                    Spacer()
                    Text("Bound to exact executable + project folder + port set")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if model.protections.isEmpty {
                            HStack(spacing: 10) {
                                Image(systemName: "shield.slash")
                                    .font(.system(size: 18))
                                    .foregroundStyle(MissionTheme.teal)
                                Text("No custom shields saved yet. Click the shield button on any process card to protect its executable, folder, and port set.")
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(16)
                            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.cardFill(colorScheme)))
                        } else {
                            ForEach(model.protections.sorted(), id: \.self) { key in
                                let parsed = parseProtectionKey(key)
                                HStack(alignment: .center, spacing: 12) {
                                    Image(systemName: "shield.fill")
                                        .foregroundStyle(MissionTheme.emerald)
                                        .font(.system(size: 15))
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack(spacing: 8) {
                                            Text(URL(fileURLWithPath: parsed.executable).lastPathComponent)
                                                .font(.system(size: 13, weight: .bold))
                                            ForEach(parsed.ports, id: \.self) { port in
                                                Text(":\(port)")
                                                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                                                    .foregroundStyle(MissionTheme.emerald)
                                                    .padding(.horizontal, 6)
                                                    .padding(.vertical, 2)
                                                    .background(MissionTheme.emerald.opacity(0.14), in: Capsule())
                                            }
                                        }
                                        Text("\(parsed.executable) · \(parsed.directory)")
                                            .font(.system(size: 11, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                            .textSelection(.enabled)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    Button("Remove") {
                                        withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                                            model.protections.remove(key)
                                            UserDefaults.standard.set(Array(model.protections), forKey: "protections")
                                        }
                                    }
                                    .buttonStyle(ChromeButtonStyle())
                                }
                                .padding(12)
                                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.cardFill(colorScheme, elevated: true)))
                                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))
                            }
                        }
                    }
                }
                .frame(minHeight: 140, maxHeight: 220)

                HStack {
                    Text("If a protected process changes its project folder or listening ports, it requires a fresh shield.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Done") { showRules = false }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                }
            }
            .padding(24)
        }
        .frame(width: 680)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
    }

    private var historySheet: some View {
        ZStack {
            MissionControlBackdrop()
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(MissionTheme.teal.opacity(0.18))
                            .frame(width: 44, height: 44)
                        Image(systemName: "clock.arrow.circlepath")
                            .font(.system(size: 21, weight: .bold))
                            .foregroundStyle(MissionTheme.teal)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Cleanup History")
                            .font(.system(size: 21, weight: .bold, design: .rounded))
                        Text("Last 200 shutdown outcomes, stored locally on this Mac.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if !model.history.isEmpty {
                        Button {
                            MissionTheme.copyToClipboard(model.history.joined(separator: "\n\n"))
                        } label: {
                            Label("Copy Log", systemImage: "doc.on.doc")
                        }
                        .buttonStyle(ChromeButtonStyle())
                    }
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if model.history.isEmpty {
                            VStack(spacing: 10) {
                                Image(systemName: "tray")
                                    .font(.system(size: 30, weight: .light))
                                    .foregroundStyle(MissionTheme.teal)
                                Text("Nothing has been stopped by Port Cleanup yet.")
                                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                                Text("Every confirmed graceful stop and identity verification outcome is recorded here.")
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(44)
                            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(MissionTheme.cardFill(colorScheme)))
                        } else {
                            ForEach(Array(model.history.enumerated()), id: \.offset) { _, entry in
                                let parts = entry.split(separator: "\n", maxSplits: 1).map(String.init)
                                let headerLine = parts.first ?? entry
                                let statusLine = parts.count > 1 ? parts[1] : ""
                                let isStopped = statusLine.lowercased().hasPrefix("stopped")
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: isStopped ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                        .foregroundStyle(isStopped ? MissionTheme.emerald : MissionTheme.amber)
                                        .font(.system(size: 16))
                                        .padding(.top, 2)
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(headerLine)
                                            .font(.system(size: 12.5, weight: .bold, design: .monospaced))
                                            .textSelection(.enabled)
                                        if !statusLine.isEmpty {
                                            Text(statusLine)
                                                .font(.system(size: 12.5))
                                                .foregroundStyle(isStopped ? .primary : MissionTheme.amber)
                                                .textSelection(.enabled)
                                        }
                                    }
                                    Spacer()
                                }
                                .padding(12)
                                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.cardFill(colorScheme, elevated: true)))
                                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 380)

                HStack {
                    Text("\(model.history.count) recorded outcome\(model.history.count == 1 ? "" : "s")")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Done") { showHistory = false }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                }
            }
            .padding(24)
        }
        .frame(width: 680)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
    }

    private var confirmationSheet: some View {
        let totalPorts = Set(confirmation.flatMap(\.ports)).count
        let totalConnections = confirmation.reduce(0) { $0 + $1.connections }
        return ZStack {
            MissionControlBackdrop()
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(MissionTheme.coral.opacity(0.18))
                            .frame(width: 46, height: 46)
                        Image(systemName: "exclamationmark.octagon.fill")
                            .font(.system(size: 24, weight: .bold))
                            .foregroundStyle(MissionTheme.coral)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Stop \(confirmation.count) Selected Process\(confirmation.count == 1 ? "" : "es")?")
                            .font(.system(size: 21, weight: .bold, design: .rounded))
                        Text("This sends graceful SIGTERM to each process below and closes all \(totalPorts) of their listening TCP ports.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                HStack(spacing: 12) {
                    HStack(spacing: 6) {
                        Image(systemName: "cpu")
                            .foregroundStyle(MissionTheme.coral)
                        Text("\(confirmation.count) process\(confirmation.count == 1 ? "" : "es")")
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                    }
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(MissionTheme.subtleWell(colorScheme), in: Capsule())

                    HStack(spacing: 6) {
                        Image(systemName: "network")
                            .foregroundStyle(MissionTheme.teal)
                        Text("\(totalPorts) listening port\(totalPorts == 1 ? "" : "s")")
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                    }
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(MissionTheme.subtleWell(colorScheme), in: Capsule())

                    if totalConnections > 0 {
                        HStack(spacing: 6) {
                            Image(systemName: "bolt.horizontal.fill")
                                .foregroundStyle(MissionTheme.amber)
                            Text("\(totalConnections) established connection\(totalConnections == 1 ? "" : "s")")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundStyle(MissionTheme.amber)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(MissionTheme.amber.opacity(0.15), in: Capsule())
                    }
                    Spacer()
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(confirmation) { row in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(row.appName)
                                        .font(.system(size: 14, weight: .bold))
                                    Text("PID \(row.pid)")
                                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .padding(.horizontal, 7).padding(.vertical, 2)
                                        .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                                    Spacer()
                                    Text(row.endpoints.joined(separator: ", "))
                                        .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                                        .foregroundStyle(MissionTheme.coral)
                                }
                                Text(row.directory)
                                    .font(.system(size: 11.5, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                if row.connections > 0 {
                                    Label("\(row.connections) established connection\(row.connections == 1 ? "" : "s") on this process will be closed", systemImage: "exclamationmark.triangle.fill")
                                        .font(.system(size: 11.5, weight: .semibold))
                                        .foregroundStyle(MissionTheme.amber)
                                }
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.cardFill(colorScheme, elevated: true)))
                            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme, accent: MissionTheme.coral), lineWidth: 1))
                        }
                    }
                }
                .frame(maxHeight: 280)

                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(MissionTheme.emerald)
                    Text("Pre-signal safety gate: UID, executable path, microsecond start identity, working directory, shield status, and exact listening ports are re-verified right before sending SIGTERM. Never force-kills.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.subtleWell(colorScheme)))

                HStack {
                    Button("Cancel") { showConfirm = false }
                        .keyboardShortcut(.cancelAction)
                        .buttonStyle(ChromeButtonStyle())
                    Spacer()
                    Button(role: .destructive) {
                        showConfirm = false
                        model.stop(confirmation)
                    } label: {
                        Label("Confirm stop selected processes", systemImage: "stop.circle.fill")
                    }
                    .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.coral))
                }
            }
            .padding(26)
        }
        .frame(width: 680)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
    }
}

// MARK: - Interactive Mission Control Process Card (PortRow)

struct PortRow: View {
    let row: Listener
    @ObservedObject var model: PortModel
    var isExpanded: Bool = false
    var onToggleExpand: (() -> Void)? = nil
    var onCopyToast: ((String) -> Void)? = nil

    @ObservedObject private var appearance = AppearanceSettings.shared
    @Environment(\.colorScheme) private var colorScheme
    @ViewState private var hovered = false

    private var isSelected: Bool { model.selected.contains(row.pid) }
    private var isProtected: Bool { model.protected(row) }
    private var isFinished: Bool { model.finished.contains(row.intentKey) }
    private var currentVerdict: Decision? { model.verdict(row) }
    private var statusAccent: Color {
        if isSelected { return MissionTheme.coral }
        return MissionTheme.verdictColor(currentVerdict, isProtected: isProtected)
    }

    private func isPortLoopbackOnly(_ port: String) -> Bool {
        let matching = row.endpoints.filter { $0.split(separator: ":").last.map(String.init) == port }
        guard !matching.isEmpty else { return true }
        return matching.allSatisfy { $0.hasPrefix("127.0.0.1:") || $0.hasPrefix("[::1]:") || $0.hasPrefix("localhost:") }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center, spacing: 16) {
                // Column 1: Selection + Process Identity
                HStack(alignment: .center, spacing: 12) {
                    Toggle(
                        "Select \(row.appName)",
                        isOn: Binding(
                            get: { isSelected },
                            set: { checked in
                                withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                                    if checked { model.selected.insert(row.pid) } else { model.selected.remove(row.pid) }
                                }
                            }
                        )
                    )
                    .labelsHidden()
                    .toggleStyle(.checkbox)
                    .disabled(model.busy || isProtected)

                    let symbol = MissionTheme.processSymbol(for: row)
                    ZStack {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(symbol.tint.opacity(colorScheme == .dark ? 0.18 : 0.14))
                            .frame(width: 36, height: 36)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .stroke(symbol.tint.opacity(0.35), lineWidth: 1)
                            )
                        Image(systemName: symbol.icon)
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(symbol.tint)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(row.appName)
                                .font(.system(size: 14, weight: .bold, design: .rounded))
                                .lineLimit(1)
                            if isFinished {
                                Text("FINISHED")
                                    .font(.system(size: 9, weight: .heavy, design: .monospaced))
                                    .foregroundStyle(MissionTheme.amber)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1.5)
                                    .background(MissionTheme.amber.opacity(0.16), in: Capsule())
                            }
                        }

                        HStack(spacing: 6) {
                            Button {
                                MissionTheme.copyToClipboard("\(row.pid)")
                                onCopyToast?("Copied PID \(row.pid)")
                            } label: {
                                Text("PID \(row.pid)")
                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                            }
                            .buttonStyle(.plain)
                            .help("Click to copy PID \(row.pid)")

                            Text("· \(MissionTheme.formatAge(row.age))")
                                .font(.system(size: 11, weight: .medium, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .help("Started \(Date(timeIntervalSince1970: Double(row.start) / 1_000_000).formatted(date: .abbreviated, time: .shortened))")
                        }
                    }
                }
                .frame(width: 240, alignment: .leading)

                // Column 2: Tactile Port Chips, Project & Client Activity
                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 6) {
                        ForEach(row.ports.prefix(5), id: \.self) { port in
                            PortChip(
                                port: port,
                                isLoopbackOnly: isPortLoopbackOnly(port),
                                isCleanupCandidate: currentVerdict == .cleanup,
                                onCopy: { copied in onCopyToast?("Copied port :\(copied)") }
                            )
                        }
                        if row.ports.count > 5 {
                            Text("+\(row.ports.count - 5) more")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 4)
                                .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                        }

                        let inbound = row.evidence?.inboundCount ?? 0
                        let scanAvail = row.evidence?.establishedScanStatus == "available"
                        HStack(spacing: 4) {
                            Circle()
                                .fill(scanAvail ? (inbound > 0 ? MissionTheme.emerald : MissionTheme.teal.opacity(0.55)) : MissionTheme.amber)
                                .frame(width: 5.5, height: 5.5)
                            Text(scanAvail ? "\(inbound) client\(inbound == 1 ? "" : "s")" : "activity unavailable")
                                .font(.system(size: 11, weight: .medium, design: .rounded))
                                .foregroundStyle(inbound > 0 ? .primary : .secondary)
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                    }

                    HStack(spacing: 8) {
                        Button {
                            MissionTheme.revealInFinder(row.directory)
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "folder.fill")
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(MissionTheme.teal)
                                Text(row.project)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(.primary)
                                    .lineLimit(1)
                                Image(systemName: "arrow.up.forward.square")
                                    .font(.system(size: 9.5))
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .buttonStyle(.plain)
                        .help("Reveal \(row.directory) in Finder")

                        if !row.ancestors.isEmpty {
                            Text("· via \(row.ancestors.prefix(2).joined(separator: " ← "))")
                                .font(.system(size: 11.5))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }

                    let summary = model.evidenceSummary(row)
                    if !summary.isEmpty {
                        HStack(spacing: 5) {
                            Image(systemName: "waveform.path.ecg")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(MissionTheme.teal)
                            Text(summary)
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                // Column 3: Jev Verdict & Evidence Reason
                VStack(alignment: .leading, spacing: 6) {
                    if isProtected {
                        VerdictBadge(
                            label: row.hardProtection != nil ? "Protected · \(row.hardProtection!)" : "Keep open · Shielded",
                            icon: "shield.fill",
                            tint: MissionTheme.emerald
                        )
                    } else if let interpretation = model.interpretations[row.pid] {
                        HStack(spacing: 8) {
                            VerdictBadge(
                                label: interpretation.label,
                                icon: interpretation.verdict == .cleanup
                                    ? "scope"
                                    : interpretation.verdict == .keep
                                        ? "checkmark.shield.fill"
                                        : "questionmark.diamond.fill",
                                tint: MissionTheme.verdictColor(interpretation.verdict)
                            )
                            Text("\(Int((interpretation.confidence * 100).rounded()))% conf")
                                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        Text(interpretation.reason)
                            .font(.system(size: 11.5))
                            .foregroundStyle(.primary.opacity(0.88))
                            .fixedSize(horizontal: false, vertical: true)
                            .lineLimit(2)
                        if interpretation.verdict == .uncertain {
                            HStack(alignment: .top, spacing: 5) {
                                Image(systemName: "info.circle.fill")
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(MissionTheme.amber)
                                    .padding(.top, 1)
                                Text(interpretation.missingFact)
                                    .font(.system(size: 11))
                                    .foregroundStyle(MissionTheme.amber)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .lineLimit(2)
                            }
                        }
                    } else if let error = model.inspectionErrors[row.pid] {
                        VerdictBadge(
                            label: "Your decision · Inspection issue",
                            icon: "exclamationmark.triangle.fill",
                            tint: MissionTheme.amber
                        )
                        Text(error)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    } else {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(model.inspections[row.pid] == nil ? MissionTheme.teal.opacity(0.45) : MissionTheme.teal)
                                .frame(width: 6, height: 6)
                            Text(model.inspections[row.pid] == nil ? "Not scanned with Jev yet" : "Evidence collected · awaiting Jev")
                                .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                                .foregroundStyle(.secondary)
                        }
                        Text("Started \(Date(timeIntervalSince1970: Double(row.start) / 1_000_000).formatted(date: .abbreviated, time: .shortened))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }

                    HStack(spacing: 8) {
                        Button("Evidence & process details…") {
                            model.inspectionTarget = row
                        }
                        .disabled(model.busy)
                        .buttonStyle(ChromeButtonStyle())
                        .controlSize(.small)

                        if let onToggleExpand {
                            Button {
                                onToggleExpand()
                            } label: {
                                HStack(spacing: 4) {
                                    Text(isExpanded ? "Hide details" : "Quick details")
                                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                                        .font(.system(size: 9, weight: .bold))
                                }
                            }
                            .buttonStyle(ChromeButtonStyle())
                            .controlSize(.small)
                        }
                    }
                }
                .frame(width: 345, alignment: .leading)

                // Column 4: Interactive Shield Button
                Button {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.72)) {
                        model.toggleProtection(row)
                    }
                } label: {
                    VStack(spacing: 3) {
                        ZStack {
                            Circle()
                                .fill(isProtected ? MissionTheme.emerald.opacity(0.18) : MissionTheme.subtleWell(colorScheme))
                                .frame(width: 34, height: 34)
                                .overlay(
                                    Circle()
                                        .stroke(isProtected ? MissionTheme.emerald.opacity(0.55) : MissionTheme.cardStroke(colorScheme), lineWidth: 1)
                                )
                            Image(systemName: isProtected ? "shield.fill" : "shield")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(isProtected ? MissionTheme.emerald : .secondary)
                        }
                        Text(isProtected ? "Shielded" : "Shield")
                            .font(.system(size: 9.5, weight: .bold, design: .rounded))
                            .foregroundStyle(isProtected ? MissionTheme.emerald : .secondary)
                    }
                }
                .buttonStyle(.plain)
                .frame(width: 58)
                .disabled(model.busy || row.hardProtection != nil)
                .help(row.hardProtection ?? "Remember this executable + project + port set as protected")
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)

            if isExpanded {
                Divider().padding(.horizontal, 18).opacity(0.4)
                HStack(alignment: .top, spacing: 20) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("EXECUTABLE & WORKING DIRECTORY")
                            .font(.system(size: 9.5, weight: .heavy, design: .monospaced))
                            .foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            Text(row.executable.isEmpty ? "Unavailable" : row.executable)
                                .font(.system(size: 11.5, design: .monospaced))
                                .textSelection(.enabled)
                            Button {
                                MissionTheme.copyToClipboard(row.executable)
                                onCopyToast?("Copied executable path")
                            } label: {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Copy executable path")
                        }
                        HStack(spacing: 6) {
                            Text(row.directory.isEmpty ? "Unknown folder" : row.directory)
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                            if !row.directory.isEmpty {
                                Button("Reveal in Finder") {
                                    MissionTheme.revealInFinder(row.directory)
                                }
                                .font(.system(size: 10.5, weight: .semibold))
                                .buttonStyle(.plain)
                                .foregroundStyle(MissionTheme.teal)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(alignment: .leading, spacing: 5) {
                        Text("BINDINGS & LINEAGE")
                            .font(.system(size: 9.5, weight: .heavy, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text("Endpoints: \(row.endpoints.joined(separator: ", "))")
                            .font(.system(size: 11.5, design: .monospaced))
                            .textSelection(.enabled)
                        Text("Parent PID \(row.parent)\(row.ancestors.isEmpty ? "" : " · " + row.ancestors.joined(separator: " ← "))")
                            .font(.system(size: 11.5))
                            .foregroundStyle(.secondary)
                        if let label = row.evidence?.launchdLabel {
                            Text("Launchd service: \(label)")
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundStyle(MissionTheme.teal)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    if !isProtected {
                        VStack(alignment: .trailing, spacing: 6) {
                            Text("PROCESS LIFETIME INTENT")
                                .font(.system(size: 9.5, weight: .heavy, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Button {
                                model.toggleFinished(row)
                            } label: {
                                Label(
                                    isFinished ? "Marked finished (undo)" : "Mark server finished",
                                    systemImage: isFinished ? "flag.checkered.circle.fill" : "flag.checkered"
                                )
                            }
                            .buttonStyle(ChromeButtonStyle())
                            .controlSize(.small)
                            .disabled(model.busy)
                        }
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
                .background(MissionTheme.subtleWell(colorScheme).opacity(0.65))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(MissionTheme.cardFill(colorScheme, elevated: hovered, selected: isSelected))
        )
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 3, style: .continuous)
                .fill(statusAccent)
                .frame(width: 4)
                .padding(.vertical, 8)
                .padding(.leading, 3)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(
                    isSelected
                        ? MissionTheme.coral.opacity(0.70)
                        : MissionTheme.cardStroke(colorScheme, accent: hovered ? statusAccent : nil, hovered: hovered),
                    lineWidth: isSelected ? 1.5 : 1
                )
        )
        .shadow(
            color: isSelected
                ? MissionTheme.coral.opacity(colorScheme == .dark ? 0.20 : 0.12)
                : Color.black.opacity(colorScheme == .dark ? (hovered ? 0.30 : 0.18) : (hovered ? 0.08 : 0.04)),
            radius: hovered || isSelected ? 8 : 4,
            y: 2
        )
        .onHover { isHovering in
            withAnimation(.spring(response: 0.22, dampingFraction: 0.8)) {
                hovered = isHovering
            }
        }
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
        Window("Port Cleanup", id: "main") {
            PortView(model: model).task { model.refresh() }
        }
        .defaultSize(width: 1280, height: 820)

        Settings {
            AppearanceSettingsView(isModalSheet: false)
        }
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
            if args.contains("--verify-typesafe-setup") { try TypeSafeConnectionChecks.run(); return }
            if args.contains("--save-typesafe-from-environment") {
                guard let key = ProcessInfo.processInfo.environment["TYPESAFE_API_KEY"] else { throw PortError("No TypeSafe key in the installer environment") }
                try TypeSafeKeyStore().save(key)
                _ = try Credential.read()
                print("TypeSafe key saved in Keychain; read-back verified. No API request made."); return
            }
            if args.contains("--verify-jev-connection") { _ = try Credential.read(); print("TypeSafe Keychain access verified; no API request made."); return }
            if args.contains("--connect-jev-from-environment") { try Credential.installFromEnvironment(); print("TypeSafe connected in Keychain; read-back verified."); return }
            if args.contains("--scan") { print(String(decoding: try JSONEncoder().encode(Scanner.scan()), as: UTF8.self)); return }
            if args.contains("--print-ask-brief") {
                let rows = try Scanner.scan()
                let snapshots = rows.map { AskFacts.snapshot($0, status: "Not analyzed yet", detail: "", selected: false) }
                let brief = AskBrief.text(rows: snapshots)
                let leaks = AskBrief.leaks(brief: brief, directories: rows.map(\.directory), executables: rows.map(\.executable))
                print(brief)
                print(leaks.isEmpty ? "leak-check: clean" : "leak-check: \(leaks.joined(separator: ", "))")
                if !leaks.isEmpty { throw PortError("Ask brief included a withheld path") }
                return
            }
            if let index = args.firstIndex(of: "--prepare-ask"), args.count > index + 1 {
                guard let agent = LocalAgent(rawValue: args[index + 1]) else { throw PortError("Unknown agent \(args[index + 1])") }
                let command = try AgentLaunch.prepare(agent: agent, brief: "Port Cleanup scan\nDry run. Do not stop any process.\n")
                print(command.path)
                return
            }
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
