import SwiftUI
import AppKit
import PortCore

// MARK: - Appearance Mode & Curated Theme Presets

enum AppColorMode: String, CaseIterable, Identifiable {
    case system = "system"
    case dark = "dark"
    case light = "light"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .system: return "System"
        case .dark: return "Dark"
        case .light: return "Light"
        }
    }

    var icon: String {
        switch self {
        case .system: return "circle.lefthalf.filled"
        case .dark: return "moon.stars.fill"
        case .light: return "sun.max.fill"
        }
    }

    var preferredScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .dark: return .dark
        case .light: return .light
        }
    }
}

struct ThemePalette {
    let darkCanvas: Color
    let lightCanvas: Color
    let darkCard: Color
    let darkCardElevated: Color
    let lightCard: Color
    let lightCardElevated: Color
    let darkWell: Color
    let lightWell: Color
    let darkTextPrimary: Color
    let lightTextPrimary: Color
    let emerald: Color      // Primary safe / keep / action accent
    let teal: Color         // Secondary radar / port / telemetry accent
    let mint: Color         // Highlight / terminal accent
    let amber: Color        // Review / uncertain accent
    let coral: Color        // Stop / cleanup accent
}

enum AppThemePreset: String, CaseIterable, Identifiable {
    case emeraldPine = "emeraldPine"
    case solarAmber = "solarAmber"
    case oceanicAbyss = "oceanicAbyss"
    case nordicFrost = "nordicFrost"
    case tokyoEmber = "tokyoEmber"
    case monokaiEspresso = "monokaiEspresso"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .emeraldPine: return "Emerald Pine"
        case .solarAmber: return "Solar Amber"
        case .oceanicAbyss: return "Oceanic Abyss"
        case .nordicFrost: return "Nordic Frost"
        case .tokyoEmber: return "Tokyo Ember"
        case .monokaiEspresso: return "Monokai Espresso"
        }
    }

    var subtitle: String {
        switch self {
        case .emeraldPine: return "Deep forest pine with emerald & seafoam radar accents"
        case .solarAmber: return "Warm espresso bronze with phosphor gold & tangerine"
        case .oceanicAbyss: return "Deep Mariana trench teal with bioluminescent aqua"
        case .nordicFrost: return "Crisp Arctic fjord slate with glacier ice & aurora sage"
        case .tokyoEmber: return "Rich roasted mahogany with sunset terracotta & jade"
        case .monokaiEspresso: return "Warm roasted coffee with classic lime, gold & coral"
        }
    }

    var badgeIcon: String {
        switch self {
        case .emeraldPine: return "leaf.fill"
        case .solarAmber: return "sun.max.fill"
        case .oceanicAbyss: return "water.waves"
        case .nordicFrost: return "snowflake"
        case .tokyoEmber: return "flame.fill"
        case .monokaiEspresso: return "cup.and.saucer.fill"
        }
    }

    var palette: ThemePalette {
        switch self {
        case .emeraldPine:
            return ThemePalette(
                darkCanvas: Color(red: 0.04, green: 0.08, blue: 0.07),
                lightCanvas: Color(red: 0.94, green: 0.97, blue: 0.95),
                darkCard: Color(red: 0.07, green: 0.13, blue: 0.11),
                darkCardElevated: Color(red: 0.09, green: 0.16, blue: 0.14),
                lightCard: Color(red: 0.97, green: 0.99, blue: 0.98),
                lightCardElevated: Color(red: 0.99, green: 1.0, blue: 0.99),
                darkWell: Color(red: 0.03, green: 0.06, blue: 0.05),
                lightWell: Color(red: 0.87, green: 0.93, blue: 0.90),
                darkTextPrimary: .white,
                lightTextPrimary: Color(red: 0.05, green: 0.14, blue: 0.10),
                emerald: Color(red: 0.16, green: 0.84, blue: 0.52),
                teal: Color(red: 0.12, green: 0.78, blue: 0.66),
                mint: Color(red: 0.32, green: 0.88, blue: 0.68),
                amber: Color(red: 0.98, green: 0.70, blue: 0.19),
                coral: Color(red: 0.96, green: 0.34, blue: 0.35)
            )
        case .solarAmber:
            return ThemePalette(
                darkCanvas: Color(red: 0.08, green: 0.06, blue: 0.04),
                lightCanvas: Color(red: 0.97, green: 0.95, blue: 0.91),
                darkCard: Color(red: 0.13, green: 0.10, blue: 0.07),
                darkCardElevated: Color(red: 0.17, green: 0.13, blue: 0.09),
                lightCard: Color(red: 0.99, green: 0.98, blue: 0.95),
                lightCardElevated: Color(red: 1.0, green: 0.99, blue: 0.97),
                darkWell: Color(red: 0.06, green: 0.04, blue: 0.03),
                lightWell: Color(red: 0.92, green: 0.89, blue: 0.82),
                darkTextPrimary: Color(red: 1.0, green: 0.97, blue: 0.92),
                lightTextPrimary: Color(red: 0.16, green: 0.11, blue: 0.05),
                emerald: Color(red: 0.26, green: 0.82, blue: 0.48),
                teal: Color(red: 0.98, green: 0.68, blue: 0.16),
                mint: Color(red: 1.0, green: 0.80, blue: 0.32),
                amber: Color(red: 0.98, green: 0.55, blue: 0.14),
                coral: Color(red: 0.96, green: 0.33, blue: 0.28)
            )
        case .oceanicAbyss:
            return ThemePalette(
                darkCanvas: Color(red: 0.03, green: 0.07, blue: 0.10),
                lightCanvas: Color(red: 0.93, green: 0.96, blue: 0.98),
                darkCard: Color(red: 0.06, green: 0.12, blue: 0.17),
                darkCardElevated: Color(red: 0.08, green: 0.16, blue: 0.22),
                lightCard: Color(red: 0.97, green: 0.99, blue: 1.0),
                lightCardElevated: Color(red: 0.99, green: 1.0, blue: 1.0),
                darkWell: Color(red: 0.02, green: 0.05, blue: 0.08),
                lightWell: Color(red: 0.86, green: 0.92, blue: 0.96),
                darkTextPrimary: .white,
                lightTextPrimary: Color(red: 0.04, green: 0.12, blue: 0.18),
                emerald: Color(red: 0.14, green: 0.84, blue: 0.64),
                teal: Color(red: 0.14, green: 0.74, blue: 0.94),
                mint: Color(red: 0.36, green: 0.86, blue: 0.96),
                amber: Color(red: 0.98, green: 0.72, blue: 0.22),
                coral: Color(red: 0.98, green: 0.36, blue: 0.40)
            )
        case .nordicFrost:
            return ThemePalette(
                darkCanvas: Color(red: 0.09, green: 0.12, blue: 0.16),
                lightCanvas: Color(red: 0.93, green: 0.95, blue: 0.97),
                darkCard: Color(red: 0.13, green: 0.17, blue: 0.22),
                darkCardElevated: Color(red: 0.16, green: 0.21, blue: 0.27),
                lightCard: Color(red: 0.97, green: 0.98, blue: 0.99),
                lightCardElevated: Color(red: 1.0, green: 1.0, blue: 1.0),
                darkWell: Color(red: 0.07, green: 0.09, blue: 0.13),
                lightWell: Color(red: 0.87, green: 0.90, blue: 0.94),
                darkTextPrimary: Color(red: 0.93, green: 0.96, blue: 0.98),
                lightTextPrimary: Color(red: 0.12, green: 0.16, blue: 0.22),
                emerald: Color(red: 0.40, green: 0.80, blue: 0.56),
                teal: Color(red: 0.36, green: 0.75, blue: 0.86),
                mint: Color(red: 0.52, green: 0.82, blue: 0.86),
                amber: Color(red: 0.94, green: 0.76, blue: 0.38),
                coral: Color(red: 0.90, green: 0.38, blue: 0.42)
            )
        case .tokyoEmber:
            return ThemePalette(
                darkCanvas: Color(red: 0.09, green: 0.05, blue: 0.05),
                lightCanvas: Color(red: 0.98, green: 0.94, blue: 0.93),
                darkCard: Color(red: 0.15, green: 0.09, blue: 0.09),
                darkCardElevated: Color(red: 0.19, green: 0.11, blue: 0.11),
                lightCard: Color(red: 1.0, green: 0.98, blue: 0.97),
                lightCardElevated: Color(red: 1.0, green: 0.99, blue: 0.99),
                darkWell: Color(red: 0.06, green: 0.03, blue: 0.03),
                lightWell: Color(red: 0.94, green: 0.88, blue: 0.86),
                darkTextPrimary: Color(red: 1.0, green: 0.96, blue: 0.95),
                lightTextPrimary: Color(red: 0.18, green: 0.08, blue: 0.08),
                emerald: Color(red: 0.22, green: 0.82, blue: 0.56),
                teal: Color(red: 0.98, green: 0.52, blue: 0.34),
                mint: Color(red: 0.99, green: 0.68, blue: 0.42),
                amber: Color(red: 0.98, green: 0.74, blue: 0.24),
                coral: Color(red: 0.98, green: 0.30, blue: 0.36)
            )
        case .monokaiEspresso:
            return ThemePalette(
                darkCanvas: Color(red: 0.10, green: 0.09, blue: 0.08),
                lightCanvas: Color(red: 0.97, green: 0.96, blue: 0.93),
                darkCard: Color(red: 0.15, green: 0.13, blue: 0.11),
                darkCardElevated: Color(red: 0.19, green: 0.17, blue: 0.14),
                lightCard: Color(red: 0.99, green: 0.99, blue: 0.97),
                lightCardElevated: Color(red: 1.0, green: 1.0, blue: 0.99),
                darkWell: Color(red: 0.07, green: 0.06, blue: 0.05),
                lightWell: Color(red: 0.91, green: 0.89, blue: 0.84),
                darkTextPrimary: Color(red: 0.98, green: 0.97, blue: 0.94),
                lightTextPrimary: Color(red: 0.16, green: 0.14, blue: 0.11),
                emerald: Color(red: 0.52, green: 0.86, blue: 0.32),
                teal: Color(red: 0.30, green: 0.84, blue: 0.78),
                mint: Color(red: 0.98, green: 0.82, blue: 0.32),
                amber: Color(red: 0.99, green: 0.60, blue: 0.24),
                coral: Color(red: 0.98, green: 0.34, blue: 0.44)
            )
        }
    }
}

@MainActor final class AppearanceSettings: ObservableObject {
    static let shared = AppearanceSettings()

    @Published var preset: AppThemePreset {
        didSet { UserDefaults.standard.set(preset.rawValue, forKey: "appearancePreset") }
    }
    @Published var colorMode: AppColorMode {
        didSet { UserDefaults.standard.set(colorMode.rawValue, forKey: "appearanceColorMode") }
    }
    @Published var ambientGlow: Bool {
        didSet { UserDefaults.standard.set(ambientGlow, forKey: "appearanceAmbientGlow") }
    }

    private init() {
        let savedPreset = UserDefaults.standard.string(forKey: "appearancePreset") ?? AppThemePreset.emeraldPine.rawValue
        self.preset = AppThemePreset(rawValue: savedPreset) ?? .emeraldPine
        let savedMode = UserDefaults.standard.string(forKey: "appearanceColorMode") ?? AppColorMode.system.rawValue
        self.colorMode = AppColorMode(rawValue: savedMode) ?? .system
        if UserDefaults.standard.object(forKey: "appearanceAmbientGlow") == nil {
            self.ambientGlow = true
        } else {
            self.ambientGlow = UserDefaults.standard.bool(forKey: "appearanceAmbientGlow")
        }
    }
}

// MARK: - Dynamic Mission Control Theme Tokens

@MainActor enum MissionTheme {
    private static var current: ThemePalette { AppearanceSettings.shared.preset.palette }

    static var emerald: Color { current.emerald }
    static var coral: Color { current.coral }
    static var amber: Color { current.amber }
    static var teal: Color { current.teal }
    static var mint: Color { current.mint }

    static func primaryText(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? current.darkTextPrimary : current.lightTextPrimary
    }

    static func canvasBackground(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? current.darkCanvas : current.lightCanvas
    }

    static func cardFill(_ scheme: ColorScheme, elevated: Bool = false, selected: Bool = false) -> Color {
        if selected {
            return scheme == .dark
                ? Color(red: 0.22, green: 0.11, blue: 0.10).opacity(0.90)
                : Color(red: 1.0, green: 0.94, blue: 0.93)
        }
        if elevated {
            return (scheme == .dark ? current.darkCardElevated : current.lightCardElevated).opacity(0.94)
        }
        return (scheme == .dark ? current.darkCard : current.lightCard).opacity(0.89)
    }

    static func cardStroke(_ scheme: ColorScheme, accent: Color? = nil, hovered: Bool = false) -> Color {
        if let accent {
            return accent.opacity(hovered ? (scheme == .dark ? 0.68 : 0.58) : (scheme == .dark ? 0.44 : 0.36))
        }
        if hovered {
            return scheme == .dark ? teal.opacity(0.36) : teal.opacity(0.30)
        }
        return scheme == .dark ? teal.opacity(0.16) : teal.opacity(0.18)
    }

    static func subtleWell(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? current.darkWell.opacity(0.65) : current.lightWell.opacity(0.78)
    }

    static func disabledFill(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? current.darkCard.opacity(0.65) : current.lightWell
    }

    static func verdictColor(_ decision: Decision?, isProtected: Bool = false) -> Color {
        if isProtected { return emerald }
        switch decision {
        case .cleanup: return coral
        case .keep: return emerald
        case .uncertain: return amber
        case nil: return teal
        }
    }

    static func formatAge(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        if s < 60 { return "\(s)s" }
        let m = s / 60
        if m < 60 { return "\(m)m" }
        let h = m / 60
        let remM = m % 60
        if h < 24 { return remM > 0 ? "\(h)h \(remM)m" : "\(h)h" }
        let d = h / 24
        let remH = h % 24
        return remH > 0 ? "\(d)d \(remH)h" : "\(d)d"
    }

    static func processSymbol(for row: Listener) -> (icon: String, tint: Color) {
        let lower = "\(row.appName) \(row.name) \(row.executable)".lowercased()
        if lower.contains("chrome") || lower.contains("chromium") || lower.contains("safari") || lower.contains("firefox") || lower.contains("webkit") {
            return ("globe.americas.fill", teal)
        }
        if lower.contains("node") || lower.contains("bun") || lower.contains("deno") || lower.contains("vite") || lower.contains("next") {
            return ("shippingbox.fill", emerald)
        }
        if lower.contains("python") || lower.contains("uvicorn") || lower.contains("gunicorn") || lower.contains("flask") {
            return ("terminal.fill", mint)
        }
        if lower.contains("ssh") || lower.contains("tunnel") || lower.contains("ngrok") || lower.contains("cloudflared") {
            return ("lock.shield.fill", amber)
        }
        if lower.contains("postgres") || lower.contains("redis") || lower.contains("mysql") || lower.contains("sqlite") || lower.contains("mongo") {
            return ("cylinder.split.1x2.fill", teal)
        }
        if row.executable.contains(".app/") {
            return ("macwindow", emerald)
        }
        return ("cpu.fill", teal)
    }

    static func copyToClipboard(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
    }

    static func revealInFinder(_ path: String) {
        guard !path.isEmpty else { return }
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
    }
}

// MARK: - Smooth Atmospheric Backdrop

struct MissionControlBackdrop: View {
    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared

    var body: some View {
        ZStack {
            MissionTheme.canvasBackground(colorScheme)
            if appearance.ambientGlow {
                GeometryReader { geo in
                    ZStack {
                        RadialGradient(
                            colors: [
                                MissionTheme.emerald.opacity(colorScheme == .dark ? 0.12 : 0.08),
                                MissionTheme.teal.opacity(colorScheme == .dark ? 0.05 : 0.03),
                                Color.clear
                            ],
                            center: .topLeading,
                            startRadius: 20,
                            endRadius: max(geo.size.width * 0.58, 440)
                        )
                        RadialGradient(
                            colors: [
                                MissionTheme.teal.opacity(colorScheme == .dark ? 0.09 : 0.05),
                                Color.clear
                            ],
                            center: .topTrailing,
                            startRadius: 10,
                            endRadius: max(geo.size.width * 0.45, 360)
                        )
                    }
                }
            }
        }
        .ignoresSafeArea()
    }
}

// MARK: - Animated Radar Orb Component

struct RadarOrb: View {
    let busy: Bool
    let cleanupCount: Int
    let uncertainCount: Int
    var size: CGFloat = 46

    @ObservedObject private var appearance = AppearanceSettings.shared
    @ViewState private var sweepAngle: Double = 0
    @ViewState private var pulseScale: CGFloat = 0.88

    private var coreColor: Color {
        if busy { return MissionTheme.teal }
        if cleanupCount > 0 { return MissionTheme.coral }
        if uncertainCount > 0 { return MissionTheme.amber }
        return MissionTheme.emerald
    }

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [coreColor.opacity(0.32), coreColor.opacity(0.06), Color.clear],
                        center: .center,
                        startRadius: 2,
                        endRadius: size * 0.65
                    )
                )
                .frame(width: size * 1.25, height: size * 1.25)
                .scaleEffect(busy ? pulseScale : 1.0)

            Circle()
                .fill(appearance.preset.palette.darkWell)
                .frame(width: size, height: size)
                .overlay(
                    Circle()
                        .stroke(coreColor.opacity(0.55), lineWidth: 1.5)
                )

            Circle()
                .stroke(coreColor.opacity(0.25), style: StrokeStyle(lineWidth: 0.8, dash: [2, 2]))
                .frame(width: size * 0.68, height: size * 0.68)

            Circle()
                .stroke(coreColor.opacity(0.20), lineWidth: 0.8)
                .frame(width: size * 0.36, height: size * 0.36)

            Path { path in
                let r = size * 0.44
                let c = size * 0.5
                path.move(to: CGPoint(x: c - r, y: c))
                path.addLine(to: CGPoint(x: c + r, y: c))
                path.move(to: CGPoint(x: c, y: c - r))
                path.addLine(to: CGPoint(x: c, y: c + r))
            }
            .stroke(coreColor.opacity(0.22), lineWidth: 0.75)
            .frame(width: size, height: size)

            AngularGradient(
                gradient: Gradient(colors: [
                    Color.clear,
                    coreColor.opacity(busy ? 0.05 : 0.02),
                    coreColor.opacity(busy ? 0.42 : 0.22)
                ]),
                center: .center,
                startAngle: .degrees(0),
                endAngle: .degrees(360)
            )
            .clipShape(Circle())
            .frame(width: size - 4, height: size - 4)
            .rotationEffect(.degrees(sweepAngle))

            if cleanupCount > 0 {
                Circle()
                    .fill(MissionTheme.coral)
                    .frame(width: 5, height: 5)
                    .shadow(color: MissionTheme.coral, radius: 3)
                    .offset(x: size * 0.20, y: -size * 0.16)
            }
            if uncertainCount > 0 {
                Circle()
                    .fill(MissionTheme.amber)
                    .frame(width: 4.5, height: 4.5)
                    .shadow(color: MissionTheme.amber, radius: 3)
                    .offset(x: -size * 0.18, y: size * 0.16)
            }

            Circle()
                .fill(coreColor)
                .frame(width: 8, height: 8)
                .shadow(color: coreColor, radius: 5)
        }
        .onAppear {
            withAnimation(.linear(duration: busy ? 2.2 : 6.0).repeatForever(autoreverses: false)) {
                sweepAngle = 360
            }
            withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
                pulseScale = 1.12
            }
        }
    }
}

// MARK: - Glowing Verdict & Status Pill

struct VerdictBadge: View {
    let label: String
    let icon: String
    let tint: Color
    var prominent: Bool = false

    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 6, height: 6)
                .shadow(color: tint.opacity(0.9), radius: 3)
            Image(systemName: icon)
                .font(.system(size: prominent ? 12 : 11, weight: .bold))
                .foregroundStyle(tint)
            Text(label)
                .font(.system(size: prominent ? 12.5 : 11.5, weight: .bold, design: .rounded))
                .foregroundStyle(MissionTheme.primaryText(colorScheme))
                .lineLimit(1)
        }
        .padding(.horizontal, prominent ? 11 : 9)
        .padding(.vertical, prominent ? 5.5 : 4)
        .background(
            Capsule()
                .fill(tint.opacity(colorScheme == .dark ? 0.18 : 0.14))
        )
        .overlay(
            Capsule()
                .stroke(tint.opacity(colorScheme == .dark ? 0.50 : 0.40), lineWidth: 1)
        )
        .shadow(color: tint.opacity(colorScheme == .dark ? 0.22 : 0.10), radius: 5, y: 1)
    }
}

// MARK: - Interactive Tactile Port Chip

struct PortChip: View {
    let port: String
    let isLoopbackOnly: Bool
    var isCleanupCandidate: Bool = false
    var onCopy: ((String) -> Void)? = nil

    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared
    @ViewState private var hovered = false
    @ViewState private var justCopied = false

    private var accent: Color {
        if justCopied { return MissionTheme.emerald }
        if isCleanupCandidate { return MissionTheme.coral }
        return isLoopbackOnly ? MissionTheme.teal : MissionTheme.amber
    }

    var body: some View {
        Button {
            MissionTheme.copyToClipboard(port)
            onCopy?(port)
            withAnimation(.spring(response: 0.25, dampingFraction: 0.7)) {
                justCopied = true
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                withAnimation(.easeOut(duration: 0.2)) {
                    justCopied = false
                }
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: justCopied ? "checkmark" : (isLoopbackOnly ? "lock.fill" : "antenna.radiowaves.left.and.right"))
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(accent)
                Text(justCopied ? "Copied :\(port)" : ":\(port)")
                    .font(.system(size: 12.5, weight: .bold, design: .monospaced))
                    .foregroundStyle(MissionTheme.primaryText(colorScheme))
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 4.5)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(
                        hovered
                            ? accent.opacity(colorScheme == .dark ? 0.24 : 0.16)
                            : MissionTheme.subtleWell(colorScheme)
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(
                        accent.opacity(hovered || justCopied ? 0.65 : (colorScheme == .dark ? 0.34 : 0.26)),
                        lineWidth: 1
                    )
            )
            .scaleEffect(hovered ? 1.03 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovering in
            withAnimation(.spring(response: 0.22, dampingFraction: 0.75)) {
                hovered = isHovering
            }
        }
        .help(isLoopbackOnly
              ? "Port \(port) (loopback only) — click to copy port number"
              : "Port \(port) (listening beyond loopback) — click to copy port number")
    }
}

// MARK: - Interactive Telemetry Stat Card

struct TelemetryStatCard: View {
    let title: String
    let subtitle: String
    let count: Int
    let icon: String
    let tint: Color
    let isActive: Bool
    var actionLabel: String? = nil
    var onAction: (() -> Void)? = nil
    let onSelect: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared
    @ViewState private var hovered = false

    var body: some View {
        Button(action: onSelect) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .center, spacing: 8) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(tint.opacity(colorScheme == .dark ? 0.20 : 0.14))
                            .frame(width: 28, height: 28)
                        Image(systemName: icon)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(tint)
                    }
                    Text(title)
                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    if isActive {
                        Text("ACTIVE")
                            .font(.system(size: 9, weight: .heavy, design: .monospaced))
                            .foregroundStyle(tint)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(tint.opacity(0.16), in: Capsule())
                    }
                }

                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(count)")
                        .font(.system(size: 26, weight: .bold, design: .rounded))
                        .foregroundStyle(MissionTheme.primaryText(colorScheme))
                    Text(subtitle)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                    if let actionLabel, let onAction, count > 0 {
                        Button {
                            onAction()
                        } label: {
                            Text(actionLabel)
                                .font(.system(size: 10.5, weight: .bold, design: .rounded))
                                .foregroundStyle(tint)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3.5)
                                .background(tint.opacity(0.16), in: Capsule())
                                .overlay(Capsule().stroke(tint.opacity(0.45), lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(MissionTheme.cardFill(colorScheme, elevated: isActive || hovered))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(
                        isActive
                            ? tint.opacity(colorScheme == .dark ? 0.75 : 0.65)
                            : MissionTheme.cardStroke(colorScheme, accent: hovered ? tint : nil, hovered: hovered),
                        lineWidth: isActive ? 1.5 : 1
                    )
            )
            .shadow(
                color: isActive ? tint.opacity(colorScheme == .dark ? 0.20 : 0.12) : Color.black.opacity(colorScheme == .dark ? 0.22 : 0.04),
                radius: isActive ? 10 : 4,
                y: 2
            )
            .scaleEffect(hovered ? 1.012 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovering in
            withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                hovered = isHovering
            }
        }
    }
}

// MARK: - Mission Control Button Styles

struct MissionPrimaryButtonStyle: ButtonStyle {
    var tint: Color = MissionTheme.emerald
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .bold, design: .rounded))
            .foregroundStyle(isEnabled ? Color.white : Color.secondary)
            .padding(.horizontal, 15)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(
                        isEnabled
                            ? LinearGradient(
                                colors: [tint, tint.opacity(0.82)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                            : LinearGradient(
                                colors: [MissionTheme.disabledFill(colorScheme), MissionTheme.disabledFill(colorScheme)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(isEnabled ? Color.white.opacity(0.28) : MissionTheme.cardStroke(colorScheme), lineWidth: 1)
            )
            .shadow(color: isEnabled ? tint.opacity(0.32) : .clear, radius: 7, y: 2)
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .animation(.spring(response: 0.2, dampingFraction: 0.75), value: configuration.isPressed)
    }
}

// MARK: - Interactive Appearance & Themes Settings View

struct AppearanceSettingsView: View {
    var isModalSheet: Bool = true
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var systemColorScheme
    @ObservedObject private var appearance = AppearanceSettings.shared

    private var effectiveScheme: ColorScheme {
        appearance.colorMode.preferredScheme ?? systemColorScheme
    }

    private let columns = [
        GridItem(.flexible(), spacing: 14),
        GridItem(.flexible(), spacing: 14)
    ]

    var body: some View {
        ZStack {
            MissionControlBackdrop()

            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(MissionTheme.emerald.opacity(0.18))
                            .frame(width: 46, height: 46)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .stroke(MissionTheme.emerald.opacity(0.45), lineWidth: 1)
                            )
                        Image(systemName: "paintbrush.pointed.fill")
                            .font(.system(size: 21, weight: .bold))
                            .foregroundStyle(MissionTheme.emerald)
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Appearance & Themes")
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                        Text("Choose your preferred Mission Control palette and light or dark mode.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if isModalSheet {
                        Button("Done") { dismiss() }
                            .keyboardShortcut(.defaultAction)
                            .buttonStyle(MissionPrimaryButtonStyle(tint: MissionTheme.emerald))
                    }
                }

                // Mode & Ambient Glow Bar
                HStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("APPEARANCE MODE")
                            .font(.system(size: 10, weight: .heavy, design: .monospaced))
                            .foregroundStyle(.secondary)

                        HStack(spacing: 8) {
                            ForEach(AppColorMode.allCases) { mode in
                                let active = appearance.colorMode == mode
                                Button {
                                    withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                                        appearance.colorMode = mode
                                    }
                                } label: {
                                    HStack(spacing: 6) {
                                        Image(systemName: mode.icon)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundStyle(active ? MissionTheme.emerald : .secondary)
                                        Text(mode.title)
                                            .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                            .foregroundStyle(active ? MissionTheme.primaryText(effectiveScheme) : .secondary)
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 7)
                                    .background(
                                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                                            .fill(active ? MissionTheme.emerald.opacity(0.18) : MissionTheme.subtleWell(effectiveScheme))
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                                            .stroke(active ? MissionTheme.emerald.opacity(0.6) : MissionTheme.cardStroke(effectiveScheme), lineWidth: 1)
                                    )
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 6) {
                        Text("ATMOSPHERE")
                            .font(.system(size: 10, weight: .heavy, design: .monospaced))
                            .foregroundStyle(.secondary)

                        Toggle(isOn: Binding(
                            get: { appearance.ambientGlow },
                            set: { val in
                                withAnimation(.easeInOut(duration: 0.25)) {
                                    appearance.ambientGlow = val
                                }
                            }
                        )) {
                            Text("Ambient radar glow")
                                .font(.system(size: 12.5, weight: .semibold, design: .rounded))
                        }
                        .toggleStyle(.switch)
                        .tint(MissionTheme.emerald)
                    }
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(MissionTheme.cardFill(effectiveScheme, elevated: true))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(MissionTheme.cardStroke(effectiveScheme), lineWidth: 1)
                )

                // Theme Gallery Grid
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("COLOR PALETTES")
                            .font(.system(size: 10.5, weight: .heavy, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("Active: \(appearance.preset.title)")
                            .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                            .foregroundStyle(MissionTheme.emerald)
                    }

                    LazyVGrid(columns: columns, spacing: 12) {
                        ForEach(AppThemePreset.allCases) { preset in
                            ThemePresetCard(
                                preset: preset,
                                isSelected: appearance.preset == preset,
                                scheme: effectiveScheme
                            ) {
                                withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) {
                                    appearance.preset = preset
                                }
                            }
                        }
                    }
                }
            }
            .padding(24)
        }
        .frame(width: 680)
        .preferredColorScheme(appearance.colorMode.preferredScheme)
    }
}

private struct ThemePresetCard: View {
    let preset: AppThemePreset
    let isSelected: Bool
    let scheme: ColorScheme
    let onSelect: () -> Void

    @ViewState private var hovered = false

    var body: some View {
        let p = preset.palette
        let canvas = scheme == .dark ? p.darkCanvas : p.lightCanvas
        let card = scheme == .dark ? p.darkCardElevated : p.lightCardElevated
        let well = scheme == .dark ? p.darkWell : p.lightWell

        Button(action: onSelect) {
            VStack(alignment: .leading, spacing: 10) {
                // Miniature UI Swatch Preview
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(canvas)
                        .frame(height: 58)
                        .overlay(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .stroke(p.teal.opacity(0.28), lineWidth: 1)
                        )

                    HStack(spacing: 10) {
                        // Mini Radar Orb Swatch
                        ZStack {
                            Circle()
                                .fill(p.darkWell)
                                .frame(width: 30, height: 30)
                                .overlay(Circle().stroke(p.teal.opacity(0.6), lineWidth: 1))
                            Circle()
                                .stroke(p.teal.opacity(0.3), lineWidth: 0.7)
                                .frame(width: 18, height: 18)
                            Circle()
                                .fill(p.emerald)
                                .frame(width: 6, height: 6)
                                .shadow(color: p.emerald, radius: 3)
                        }

                        // Mini Process Card Swatch
                        HStack(spacing: 6) {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(p.emerald)
                                .frame(width: 3, height: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 4) {
                                    Text(":3000")
                                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                        .foregroundStyle(scheme == .dark ? p.darkTextPrimary : p.lightTextPrimary)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 2)
                                        .background(well, in: RoundedRectangle(cornerRadius: 4))
                                        .overlay(RoundedRectangle(cornerRadius: 4).stroke(p.teal.opacity(0.45), lineWidth: 0.8))

                                    Text("Keep")
                                        .font(.system(size: 9, weight: .bold, design: .rounded))
                                        .foregroundStyle(p.emerald)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 2)
                                        .background(p.emerald.opacity(0.16), in: Capsule())
                                }

                                HStack(spacing: 4) {
                                    Circle().fill(p.emerald).frame(width: 6, height: 6)
                                    Circle().fill(p.teal).frame(width: 6, height: 6)
                                    Circle().fill(p.mint).frame(width: 6, height: 6)
                                    Circle().fill(p.amber).frame(width: 6, height: 6)
                                    Circle().fill(p.coral).frame(width: 6, height: 6)
                                }
                            }
                            Spacer()
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(card, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    }
                    .padding(.horizontal, 10)
                }

                // Title & Active Badge
                HStack(spacing: 6) {
                    Image(systemName: preset.badgeIcon)
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(p.emerald)
                    Text(preset.title)
                        .font(.system(size: 13.5, weight: .bold, design: .rounded))
                        .foregroundStyle(MissionTheme.primaryText(scheme))
                    Spacer()
                    if isSelected {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 11))
                            Text("ACTIVE")
                                .font(.system(size: 9, weight: .heavy, design: .monospaced))
                        }
                        .foregroundStyle(p.emerald)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2.5)
                        .background(p.emerald.opacity(0.16), in: Capsule())
                    }
                }

                Text(preset.subtitle)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(MissionTheme.cardFill(scheme, elevated: isSelected || hovered))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(
                        isSelected
                            ? p.emerald.opacity(0.80)
                            : MissionTheme.cardStroke(scheme, accent: hovered ? p.teal : nil, hovered: hovered),
                        lineWidth: isSelected ? 2 : 1
                    )
            )
            .shadow(
                color: isSelected ? p.emerald.opacity(scheme == .dark ? 0.22 : 0.12) : Color.black.opacity(scheme == .dark ? 0.20 : 0.04),
                radius: isSelected ? 9 : 4,
                y: 2
            )
            .scaleEffect(hovered ? 1.015 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovering in
            withAnimation(.spring(response: 0.22, dampingFraction: 0.78)) {
                hovered = isHovering
            }
        }
    }
}
