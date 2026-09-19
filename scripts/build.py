#!/usr/bin/env python3
"""Build and install the local-only native app; no key handling or network calls."""
from pathlib import Path
import argparse
import plistlib
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--destination", type=Path, default=root / ".build" / "Port Cleanup.app")
a = p.parse_args()
app = a.destination.resolve()
identifier = "ai.epiphany.port-cleanup"
if app.exists():
    info = app / "Contents/Info.plist"
    if not info.exists() or plistlib.loads(info.read_bytes()).get("CFBundleIdentifier") != identifier:
        raise SystemExit("Refusing to overwrite an unrelated app")
subprocess.run(["swift", "build", "-c", "release", "--product", "PortCleanup"], cwd=root, check=True)
bin_dir = Path(subprocess.check_output(["swift", "build", "-c", "release", "--show-bin-path"], cwd=root, text=True).strip())
iconset = root / ".build" / "PortCleanup.iconset"
iconset.mkdir(parents=True, exist_ok=True)
subprocess.run(["swift", str(root / "scripts/icon.swift"), str(iconset)], check=True)
icon = root / ".build/PortCleanup.icns"
subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(icon)], check=True)
(app / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
(app / "Contents/Resources").mkdir(parents=True, exist_ok=True)
shutil.copy2(bin_dir / "PortCleanup", app / "Contents/MacOS/PortCleanup")
shutil.copy2(icon, app / "Contents/Resources/PortCleanup.icns")
info = {
    "CFBundleIdentifier": identifier, "CFBundleName": "Port Cleanup",
    "CFBundleDisplayName": "Port Cleanup", "CFBundleExecutable": "PortCleanup",
    "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.5",
    "CFBundleVersion": "6", "CFBundleIconFile": "PortCleanup",
    "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
    "NSPrincipalClass": "NSApplication", "LSApplicationCategoryType": "public.app-category.utilities",
    "NSHumanReadableCopyright": "Epiphany Dynamics",
}
(app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
subprocess.run(["codesign", "--force", "--sign", "-", "--identifier", identifier, str(app)], check=True)
subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", str(app)], check=True)
print(f"Installed and signature-verified: {app}")
