#!/usr/bin/env python3
"""
Bridger Target APK Pairer (`pair_target_apk.py`)

Patches any Android APK so it shares the same Linux UID (`android:sharedUserId`)
and signing certificate as Bridger, enabling cross-process `/data/data/<pkg>` and
`/proc/<pid>/mem` access without root.

What it does:
  1. Decodes only `AndroidManifest.xml` (leaving DEX untouched via `apktool d -s`)
  2. Sets `android:sharedUserId="<shared_uid>"` on `<manifest>`
  3. Sets `android:debuggable="true"` on `<application>` (optional, enabled by default)
  4. Rebuilds, page-aligns (`zipalign -p -f 4`), and optionally signs with the shared keystore

Usage:
  python pair_target_apk.py --in app.apk --out app_paired.apk --shared-uid io.bridger.shared --sign
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from build_bridger import (
    ANDROID_NS,
    DEFAULT_KS,
    DEFAULT_KS_ALIAS,
    DEFAULT_KS_PASS,
    ensure_keystore,
    find_apktool_jar,
    find_apksigner,
    find_zipalign,
    sign_apk,
    zipalign_apk,
)


def patch_manifest_xml(manifest_path: pathlib.Path, shared_uid: str, debuggable: bool = True) -> dict:
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    pkg_name = root.attrib.get("package", "")
    old_uid = root.attrib.get(f"{{{ANDROID_NS}}}sharedUserId", "")
    root.set(f"{{{ANDROID_NS}}}sharedUserId", shared_uid)

    app_el = root.find("application")
    if app_el is not None and debuggable:
        app_el.set(f"{{{ANDROID_NS}}}debuggable", "true")

    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    return {"package": pkg_name, "old_shared_uid": old_uid, "new_shared_uid": shared_uid, "debuggable": debuggable}


def pair_apk(
    input_apk: pathlib.Path,
    output_apk: pathlib.Path,
    shared_uid: str = "io.bridger.shared",
    debuggable: bool = True,
    sign: bool = False,
    keystore: pathlib.Path = DEFAULT_KS,
    ks_pass: str = DEFAULT_KS_PASS,
    ks_alias: str = DEFAULT_KS_ALIAS,
) -> dict:
    apktool_jar = find_apktool_jar()
    zipalign = find_zipalign()

    with tempfile.TemporaryDirectory(prefix="bridger_pair_") as tmp:
        tmp_dir = pathlib.Path(tmp)
        decoded_dir = tmp_dir / "decoded"
        unsigned_apk = tmp_dir / "unsigned.apk"
        aligned_apk = tmp_dir / "aligned.apk"

        subprocess.run(
            ["java", "-jar", str(apktool_jar), "d", "-f", "-s", str(input_apk), "-o", str(decoded_dir)],
            check=True,
        )
        manifest_path = decoded_dir / "AndroidManifest.xml"
        info = patch_manifest_xml(manifest_path, shared_uid=shared_uid, debuggable=debuggable)

        subprocess.run(
            ["java", "-jar", str(apktool_jar), "b", str(decoded_dir), "-o", str(unsigned_apk)],
            check=True,
        )
        zipalign_apk(zipalign, unsigned_apk, aligned_apk)
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(aligned_apk, output_apk)

        if sign:
            ks = ensure_keystore(keystore)
            apksigner = find_apksigner()
            sign_apk(apksigner, output_apk, ks, ks_pass, ks_alias)

        info["signed"] = sign
        info["output_apk"] = str(output_apk)
        info["size_bytes"] = output_apk.stat().st_size
        return info


def main() -> int:
    ap = argparse.ArgumentParser(description="Pair a target APK with Bridger's sharedUserId")
    ap.add_argument("--in", dest="input_apk", required=True, help="Input APK path")
    ap.add_argument("--out", dest="output_apk", required=True, help="Output paired APK path")
    ap.add_argument("--shared-uid", default="io.bridger.shared", help="Shared user ID to inject (default: io.bridger.shared)")
    ap.add_argument("--no-debuggable", action="store_true", help="Do not force android:debuggable=true")
    ap.add_argument("--sign", action="store_true", help="Sign the output APK with the shared keystore")
    ap.add_argument("--keystore", default=str(DEFAULT_KS), help="Keystore path")
    ap.add_argument("--ks-pass", default=DEFAULT_KS_PASS, help="Keystore password")
    ap.add_argument("--ks-alias", default=DEFAULT_KS_ALIAS, help="Keystore alias")
    args = ap.parse_args()

    res = pair_apk(
        input_apk=pathlib.Path(args.input_apk).resolve(),
        output_apk=pathlib.Path(args.output_apk).resolve(),
        shared_uid=args.shared_uid,
        debuggable=not args.no_debuggable,
        sign=args.sign,
        keystore=pathlib.Path(args.keystore).resolve(),
        ks_pass=args.ks_pass,
        ks_alias=args.ks_alias,
    )
    print(f"[+] Paired APK ready: {res}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
