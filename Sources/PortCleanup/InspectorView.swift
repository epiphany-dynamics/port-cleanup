import SwiftUI
import PortCore

struct InspectorView: View {
    let row: Listener
    @ObservedObject var model: PortModel
    @ObservedObject private var appearance = AppearanceSettings.shared
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    @ViewState private var report: InspectionReport?
    @ViewState private var interpretation: EvidenceInterpretation?
    @ViewState private var busy = false
    @ViewState private var error: String?
    @ViewState private var showConnection = false
    @ViewState private var copiedNote: String? = nil

    init(row: Listener, model: PortModel, initialReport: InspectionReport? = nil, initialInterpretation: EvidenceInterpretation? = nil) {
        self.row = row
        self.model = model
        _report = ViewState(initialValue: initialReport)
        _interpretation = ViewState(initialValue: initialInterpretation)
    }

    private func flashCopy(_ label: String) {
        withAnimation(.spring(response: 0.25, dampingFraction: 0.75)) {
            copiedNote = label
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
            withAnimation(.easeOut(duration: 0.2)) {
                if copiedNote == label { copiedNote = nil }
            }
        }
    }

    var body: some View {
        ZStack {
            MissionControlBackdrop()

            VStack(alignment: .leading, spacing: 0) {
                headerBar
                Divider().opacity(0.4)

                if let error {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(MissionTheme.amber)
                        Text(error)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(MissionTheme.amber)
                            .textSelection(.enabled)
                        Spacer()
                    }
                    .padding(.horizontal, 24)
                    .padding(.vertical, 10)
                    .background(MissionTheme.amber.opacity(0.12))
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        if let r = report {
                            jevSectionCard(r)

                            dossierCard(
                                title: "Launch History · Why This Process Was Created",
                                icon: "clock.arrow.circlepath",
                                tint: MissionTheme.teal
                            ) {
                                Text(r.launchHistory.status)
                                    .font(.system(size: 13, weight: .medium))
                                if let task = r.launchHistory.task {
                                    detailRow("Likely originating task (local history)", task)
                                }
                                if let session = r.launchHistory.sessionID {
                                    detailRow("Hermes session", session, monospaced: true)
                                }
                                if let ended = r.launchHistory.sessionEndedAt {
                                    HStack(alignment: .top, spacing: 8) {
                                        Image(systemName: "exclamationmark.circle.fill")
                                            .foregroundStyle(MissionTheme.amber)
                                            .padding(.top, 2)
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text("Originating session closed \(Date(timeIntervalSince1970: ended).formatted(date: .abbreviated, time: .standard))")
                                                .font(.system(size: 12.5, weight: .bold))
                                                .foregroundStyle(MissionTheme.amber)
                                            Text("Recorded reason: \(r.launchHistory.endReason ?? "unspecified"). A closed session does not prove the task succeeded or that nobody reused this process.")
                                                .font(.system(size: 11.5))
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                    .padding(10)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(MissionTheme.amber.opacity(0.10), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                }
                                Text(r.launchHistory.laterReuse)
                                    .font(.system(size: 11.5))
                                    .foregroundStyle(.secondary)
                            }

                            dossierCard(
                                title: "1 · Owner, Identity & Startup Telemetry",
                                icon: "terminal.fill",
                                tint: MissionTheme.mint
                            ) {
                                detailRow("Executable", r.process.executable, monospaced: true, copyable: true)
                                HStack(alignment: .bottom) {
                                    detailRow("Working project folder", r.process.directory, monospaced: true, copyable: true)
                                    if !r.process.directory.isEmpty {
                                        Button {
                                            MissionTheme.revealInFinder(r.process.directory)
                                        } label: {
                                            Label("Reveal in Finder", systemImage: "folder")
                                        }
                                        .buttonStyle(ChromeButtonStyle())
                                        .controlSize(.small)
                                    }
                                }
                                HStack(spacing: 24) {
                                    detailRow("Started", "\(Date(timeIntervalSince1970: Double(r.process.start) / 1_000_000).formatted(date: .abbreviated, time: .standard)) (\(MissionTheme.formatAge(r.process.age)) ago)")
                                    detailRow("All listening addresses", r.process.endpoints.joined(separator: ", "), monospaced: true)
                                }
                                detailRow(
                                    "Parent & lineage",
                                    r.process.parent == 1
                                        ? "PID 1 · original parent exited or process was daemonized. This does not prove abandonment."
                                        : "PID \(r.process.parent) · \(r.process.ancestors.joined(separator: " ← "))"
                                )
                                detailRow(
                                    "Startup arguments (allowlisted safe subset)",
                                    r.startup.available
                                        ? (r.startup.safeArguments.isEmpty
                                            ? "No allowlisted startup arguments identified; raw command was not exposed."
                                            : r.startup.safeArguments.joined(separator: " "))
                                        : "Unavailable",
                                    monospaced: !r.startup.safeArguments.isEmpty
                                )
                                if let label = r.process.evidence?.launchdLabel {
                                    detailRow("Service registration", "\(label) · registration is not proof this work is still needed", monospaced: true)
                                }
                            }

                            dossierCard(
                                title: "2 · What Is Connected to It (\(r.peers.count) Peer\(r.peers.count == 1 ? "" : "s"))",
                                icon: "point.3.connected.trianglepath.dotted",
                                tint: MissionTheme.emerald
                            ) {
                                Text(r.peerStatus)
                                    .font(.system(size: 12.5, weight: .medium))
                                ForEach(r.peers, id: \.process.pid) { peer in
                                    VStack(alignment: .leading, spacing: 6) {
                                        HStack {
                                            Image(systemName: "link.circle.fill")
                                                .foregroundStyle(MissionTheme.emerald)
                                            Text("\(peer.process.appName)")
                                                .font(.system(size: 13, weight: .bold))
                                            Text("PID \(peer.process.pid)")
                                                .font(.system(size: 11, weight: .bold, design: .monospaced))
                                                .padding(.horizontal, 6).padding(.vertical, 2)
                                                .background(MissionTheme.subtleWell(colorScheme), in: Capsule())
                                            Spacer()
                                            Text("Started \(Date(timeIntervalSince1970: Double(peer.process.start) / 1_000_000).formatted(date: .abbreviated, time: .shortened))")
                                                .font(.system(size: 11))
                                                .foregroundStyle(.secondary)
                                        }
                                        detailRow("Executable", peer.process.executable, monospaced: true)
                                        detailRow("Startup", peer.startup.safeArguments.joined(separator: " ").isEmpty ? "No allowlisted arguments found" : peer.startup.safeArguments.joined(separator: " "), monospaced: true)
                                        HStack(spacing: 20) {
                                            detailRow("Folder", peer.process.directory, monospaced: true)
                                            detailRow("Parent app", "\(peer.parentApp ?? "Unavailable") · PID \(peer.process.parent)")
                                        }
                                        if let session = peer.harnessSession {
                                            detailRow("Browser harness session", "\(session) · tool-session name, not a verified agent conversation", monospaced: true)
                                        }
                                    }
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(MissionTheme.subtleWell(colorScheme)))
                                    .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1))
                                }
                                HStack(spacing: 6) {
                                    Image(systemName: "info.circle.fill")
                                        .foregroundStyle(MissionTheme.amber)
                                    Text("A browser controller or another browser can remain connected after the original task ends. Connected ≠ currently needed.")
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundStyle(MissionTheme.amber)
                                }
                            }

                            dossierCard(
                                title: "3 · Actual Browser Workload & Linked Preview Servers",
                                icon: "globe",
                                tint: MissionTheme.teal
                            ) {
                                Text(r.browserStatus)
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(.secondary)
                                if !r.pages.isEmpty {
                                    VStack(alignment: .leading, spacing: 6) {
                                        ForEach(Array(r.pages.enumerated()), id: \.offset) { _, page in
                                            HStack(spacing: 8) {
                                                Text(page.type.uppercased())
                                                    .font(.system(size: 9.5, weight: .heavy, design: .monospaced))
                                                    .foregroundStyle(MissionTheme.teal)
                                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                                    .background(MissionTheme.teal.opacity(0.15), in: Capsule())
                                                Text(page.title)
                                                    .font(.system(size: 12.5, weight: .semibold))
                                                    .lineLimit(1)
                                                Spacer()
                                                Text(page.origin)
                                                    .font(.system(size: 11.5, design: .monospaced))
                                                    .foregroundStyle(.secondary)
                                            }
                                            .padding(.horizontal, 10).padding(.vertical, 7)
                                            .background(MissionTheme.subtleWell(colorScheme), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                        }
                                    }
                                }
                                ForEach(r.relatedServers) { server in
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Image(systemName: "server.rack")
                                                .foregroundStyle(MissionTheme.amber)
                                            Text("Page points to port \(server.ports.joined(separator: ", ")) · server PID \(server.pid)")
                                                .font(.system(size: 12.5, weight: .bold))
                                        }
                                        Text(server.directory)
                                            .font(.system(size: 11.5, design: .monospaced))
                                            .textSelection(.enabled)
                                        Text("Separate server process. Stopping this browser does not directly stop that server.")
                                            .font(.system(size: 11))
                                            .foregroundStyle(.secondary)
                                    }
                                    .padding(10)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(MissionTheme.amber.opacity(0.10), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                }
                            }

                            dossierCard(
                                title: "4 · What Is Still Unknown",
                                icon: "questionmark.diamond.fill",
                                tint: MissionTheme.amber
                            ) {
                                ForEach(r.unknowns, id: \.self) { item in
                                    HStack(alignment: .top, spacing: 8) {
                                        Circle()
                                            .fill(MissionTheme.amber)
                                            .frame(width: 5, height: 5)
                                            .padding(.top, 6)
                                        Text(item)
                                            .font(.system(size: 12.5))
                                    }
                                }
                                Text("Nothing above proves this is a stale port or guarantees it is safe to close. These are the facts for your decision.")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(MissionTheme.amber)
                                    .padding(.top, 2)
                            }

                            dossierCard(
                                title: "If You Choose to Stop It",
                                icon: "exclamationmark.triangle.fill",
                                tint: MissionTheme.coral
                            ) {
                                Text("Only PID \(r.process.pid) receives a graceful stop request (SIGTERM). All its listening ports and connections close; connected clients above may lose their browser connection. Separate preview servers are not directly signalled. Unsaved work in this process may be lost.")
                                    .font(.system(size: 12.5))
                                Text("Collected \(r.collectedAt.formatted(date: .abbreviated, time: .standard)). Snapshot only; click Refresh evidence to re-verify.")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.secondary)
                            }
                        } else {
                            VStack(spacing: 14) {
                                RadarOrb(busy: busy, cleanupCount: 0, uncertainCount: 0, size: 64)
                                Text(busy ? "Collecting process, peer & workload evidence…" : "No inspection available.")
                                    .font(.system(size: 15, weight: .bold, design: .rounded))
                                Text("Reading safe startup arguments, local socket peers, and verified headless browser targets.")
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(48)
                        }
                    }
                    .padding(24)
                }

                Divider().opacity(0.4)
                footerBar
            }
        }
        .frame(minWidth: 780, maxWidth: 940, minHeight: 700, maxHeight: 920)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
        .task { if report == nil { load() } }
        .sheet(isPresented: $showConnection) {
            TypeSafeConnectionView { error = nil }
        }
    }

    @ViewBuilder
    private var headerBar: some View {
        let symbol = MissionTheme.processSymbol(for: row)
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(symbol.tint.opacity(0.18))
                    .frame(width: 46, height: 46)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(symbol.tint.opacity(0.4), lineWidth: 1)
                    )
                Image(systemName: symbol.icon)
                    .font(.system(size: 21, weight: .bold))
                    .foregroundStyle(symbol.tint)
            }

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(row.appName)
                        .font(.system(size: 21, weight: .bold, design: .rounded))
                    ForEach(row.ports, id: \.self) { port in
                        PortChip(
                            port: port,
                            isLoopbackOnly: true,
                            isCleanupCandidate: interpretation?.verdict == .cleanup,
                            onCopy: { p in flashCopy("Copied :\(p)") }
                        )
                    }
                    if let copiedNote {
                        Text(copiedNote)
                            .font(.system(size: 11, weight: .bold, design: .rounded))
                            .foregroundStyle(MissionTheme.emerald)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(MissionTheme.emerald.opacity(0.15), in: Capsule())
                    }
                }
                HStack(spacing: 8) {
                    Text("PID \(row.pid) · \(row.project) · Up \(MissionTheme.formatAge(row.age))")
                        .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if let report, report.startup.headless {
                        Text("· Headless browser (\(report.pages.filter { $0.type == "page" }.count) page targets)")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(MissionTheme.teal)
                    }
                }
            }

            Spacer()

            HStack(spacing: 10) {
                if busy { ProgressView().controlSize(.small) }
                Button { load() } label: {
                    Label("Refresh evidence", systemImage: "arrow.clockwise")
                }
                .disabled(busy)
                .buttonStyle(ChromeButtonStyle())

                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
        .background(MissionTheme.cardFill(colorScheme, elevated: true))
    }

    @ViewBuilder
    private func jevSectionCard(_ r: InspectionReport) -> some View {
        let isProt = model.protected(row)
        let accent = isProt ? MissionTheme.emerald : MissionTheme.verdictColor(interpretation?.verdict)
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("5 · Jev's Recommendation & Evidence Verdict", systemImage: "sparkles")
                    .font(.system(size: 14, weight: .bold, design: .rounded))
                    .foregroundStyle(accent)
                Spacer()
                if let interpretation {
                    HStack(spacing: 6) {
                        Text("Confidence")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(.secondary)
                        Text("\(Int((interpretation.confidence * 100).rounded()))%")
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundStyle(accent)
                    }
                    .padding(.horizontal, 9).padding(.vertical, 3.5)
                    .background(accent.opacity(0.14), in: Capsule())
                }
            }

            if let interpretation {
                HStack(spacing: 10) {
                    VerdictBadge(
                        label: isProt ? "Keep open · Protected by Shield" : interpretation.label,
                        icon: isProt ? "shield.fill" : (interpretation.verdict == .cleanup ? "scope" : interpretation.verdict == .keep ? "checkmark.shield.fill" : "questionmark.diamond.fill"),
                        tint: accent,
                        prominent: true
                    )
                }
                Text(interpretation.reason)
                    .font(.system(size: 13.5, weight: .medium))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "magnifyingglass.circle.fill")
                        .foregroundStyle(MissionTheme.amber)
                    Text(interpretation.missingFact)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(MissionTheme.amber)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Evidence-backed recommendation, not a guarantee. You confirm every shutdown.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            } else {
                Text("Jev receives this local inspection—including startup context, named peers, and the local browser workload—not merely app names and socket counts.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 12) {
                Button {
                    interpret()
                } label: {
                    Label(interpretation == nil ? "Interpret this evidence with Jev" : "Re-interpret with Jev", systemImage: "sparkles")
                }
                .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                .disabled(busy)

                Text("One paid request per click · Minimized evidence only · Never stops a process.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(MissionTheme.cardFill(colorScheme, elevated: true))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(MissionTheme.cardStroke(colorScheme, accent: accent), lineWidth: 1.5)
        )
    }

    @ViewBuilder
    private var footerBar: some View {
        let isProt = model.protected(row)
        let isSelected = model.selected.contains(row.pid)
        HStack(spacing: 12) {
            HStack(spacing: 6) {
                Image(systemName: "hand.raised.shield.fill")
                    .foregroundStyle(MissionTheme.emerald)
                Text("You decide. Inspection never stops a process.")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button {
                model.toggleProtection(row)
            } label: {
                Label(isProt ? "Protected by Shield" : "Shield this process", systemImage: isProt ? "shield.fill" : "shield")
            }
            .buttonStyle(ChromeButtonStyle())
            .disabled(busy || row.hardProtection != nil)

            Button {
                if isSelected {
                    model.selected.remove(row.pid)
                } else {
                    model.selected.insert(row.pid)
                }
                dismiss()
            } label: {
                Label(
                    isSelected ? "Selected for cleanup (Done)" : "Select this process for cleanup",
                    systemImage: isSelected ? "checkmark.circle.fill" : "plus.circle.fill"
                )
            }
            .disabled(busy || report == nil || isProt)
            .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.coral))
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 14)
        .background(MissionTheme.cardFill(colorScheme, elevated: true))
    }

    @ViewBuilder
    private func dossierCard<Content: View>(title: String, icon: String, tint: Color, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(tint)
                Text(title)
                    .font(.system(size: 13.5, weight: .bold, design: .rounded))
            }
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(MissionTheme.cardFill(colorScheme))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(MissionTheme.cardStroke(colorScheme), lineWidth: 1)
        )
    }

    private func detailRow(_ title: String, _ value: String, monospaced: Bool = false, copyable: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(title.uppercased())
                    .font(.system(size: 10, weight: .heavy, design: .monospaced))
                    .foregroundStyle(.secondary)
                if copyable && !value.isEmpty {
                    Button {
                        MissionTheme.copyToClipboard(value)
                        flashCopy("Copied \(title.lowercased())")
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 9.5))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Copy \(title)")
                }
            }
            Text(value)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12.5))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
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
        guard TypeSafeKeyStore().isSaved else { showConnection = true; return }
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
