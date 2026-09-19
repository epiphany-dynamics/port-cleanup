#!/usr/bin/env python3
"""Build the native app bundle, sign it, and optionally package a DMG."""
from pathlib import Path
import argparse
import os
import plistlib
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--destination", type=Path, default=root / ".build" / "Port Cleanup.app")
p.add_argument("--identity", default=None,
               help="codesign identity string; overrides PORT_CLEANUP_CODESIGN_IDENTITY")
p.add_argument("--ad-hoc", action="store_true",
               help="sign with the ad-hoc identity for local development")
p.add_argument("--dmg", type=Path, default=None,
               help="write a DMG containing the signed app to this path")
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
    "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.6",
    "CFBundleVersion": "7", "CFBundleIconFile": "PortCleanup",
    "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
    "NSPrincipalClass": "NSApplication", "LSApplicationCategoryType": "public.app-category.utilities",
    "NSHumanReadableCopyright": "Epiphany Dynamics",
}
(app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
default_identity = "Developer ID Application: Epiphany Dynamics LLC (N7CB2S58ZF)"
identities = subprocess.run(["security", "find-identity", "-p", "codesigning", "-v"],
                            capture_output=True, text=True).stdout
identity_present = default_identity in identities
if a.ad_hoc:
    identity = "-"
elif a.identity:
    identity = a.identity
else:
    env_identity = os.environ.get("PORT_CLEANUP_CODESIGN_IDENTITY")
    identity = env_identity if env_identity else (default_identity if identity_present else "-")
    if not identity_present and not env_identity:
        print("No Developer ID identity installed; falling back to ad-hoc signing.")
sign_cmd = ["codesign", "--force", "--sign", identity, "--identifier", identifier]
if identity != "-":
    sign_cmd += ["--options", "runtime"]
sign_cmd.append(str(app))
subprocess.run(sign_cmd, check=True)
subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", str(app)], check=True)
if identity != "-":
    gatekeeper = subprocess.run(["spctl", "--assess", "--type", "execute", str(app)],
                                capture_output=True, text=True)
    if gatekeeper.returncode == 0:
        print("Gatekeeper assessment: accepted")
    else:
        print("Gatekeeper assessment: rejected (signature valid but not notarized; "
              "run notarytool before public distribution)")
print(f"Signature-verified app: {app}")

if a.dmg:
    dmg = a.dmg.resolve()
    dmg.parent.mkdir(parents=True, exist_ok=True)
    if dmg.exists():
        dmg.unlink()
    staging = root / ".build" / "dmg-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    shutil.copytree(app, staging / app.name)
    subprocess.run(["hdiutil", "create", "-volname", "Port Cleanup", "-srcfolder", str(staging),
                    "-format", "UDZO", "-ov", str(dmg)], check=True)
    print(f"DMG written: {dmg}")
