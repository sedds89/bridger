#!/usr/bin/env python3
"""
Bridger Standalone Source Build System (`build_bridger.py`)

Compiles Bridger from C11 + Java source code:
  1. Compiles `src/native/bridger_jni.c` -> `libbridger.so` (arm64-v8a JNI library)
  2. Compiles `src/native/bridger_memtool.c` -> `bridger_memtool` (and `libbridger_memtool.so` for SELinux exec)
  3. Compiles `src/native/bridger_ptrace_bp.c` -> `bridger_ptrace_bp` (and `libbridger_ptrace_bp.so` for SELinux exec)
  4. Compiles `src/main/java/**/*.java` -> `.class` -> `classes.dex` (via `javac` + `d8`)
  5. Compiles `src/main/res` + `src/main/AndroidManifest.xml` (via `aapt2`) with configurable
     `--package` and `--shared-uid`
  6. Packages and page-aligns (`zipalign -p -f 4`) the APK, and optionally signs (`--sign`)
     with a user keystore or an auto-generated local debug keystore.

Environment Variables (optional overrides):
  ANDROID_SDK_ROOT / ANDROID_HOME  : Path to Android SDK
  ANDROID_NDK_HOME / ANDROID_NDK_ROOT : Path to Android NDK
  FRIDA_GADGET_SO                  : Path to libfrida-gadget.so (for --with-gadget)
  APKTOOL_JAR                      : Path to apktool.jar (used by pair_target_apk.py)

Usage:
  python build_bridger.py
  python build_bridger.py --sign
  python build_bridger.py --package io.bridger.custom --shared-uid com.example.shared --sign
"""

from __future__ import annotations

import argparse
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, List, Optional

ROOT = pathlib.Path(__file__).resolve().parent
SRC_JAVA = ROOT / "src" / "main" / "java"
SRC_RES = ROOT / "src" / "main" / "res"
SRC_MANIFEST = ROOT / "src" / "main" / "AndroidManifest.xml"
SRC_NATIVE = ROOT / "src" / "native"
GADGET_CFG = ROOT / "client" / "frida" / "gadget.config.json"

DIST_DIR = ROOT / "dist"
DIST_BIN_DIR = DIST_DIR / "bin" / "arm64-v8a"
KEYSTORE_DIR = ROOT / "keystore"

DEFAULT_KS = KEYSTORE_DIR / "debug.keystore"
DEFAULT_KS_PASS = "android"
DEFAULT_KS_ALIAS = "bridgerdebug"

ANDROID_NS = "http://schemas.android.com/apk/res/android"
IS_WINDOWS = platform.system().lower().startswith("win")


def _sdk_roots() -> List[pathlib.Path]:
    roots: List[pathlib.Path] = []
    for env_key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        val = os.environ.get(env_key, "").strip()
        if val:
            roots.append(pathlib.Path(val))
    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if local_appdata:
        roots.append(pathlib.Path(local_appdata) / "Android" / "Sdk")
    roots.extend(
        [
            pathlib.Path("C:/Android/Sdk"),
            pathlib.Path.home() / "Android" / "Sdk",
            pathlib.Path.home() / "Library" / "Android" / "sdk",
            pathlib.Path("/opt/android-sdk"),
        ]
    )
    return [r for r in roots if r.is_dir()]


def find_first_existing(candidates: List[pathlib.Path], label: str) -> pathlib.Path:
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        f"Could not find {label}. Set ANDROID_SDK_ROOT / ANDROID_NDK_HOME or check: {[str(c) for c in candidates]}"
    )


def find_ndk_clang() -> pathlib.Path:
    exe_name = "clang.exe" if IS_WINDOWS else "clang"
    which_clang = shutil.which("aarch64-linux-android24-clang")
    if which_clang:
        return pathlib.Path(which_clang)

    candidates: List[pathlib.Path] = []
    for env_key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT"):
        val = os.environ.get(env_key, "").strip()
        if val:
            ndk_dir = pathlib.Path(val)
            candidates.extend(ndk_dir.glob(f"toolchains/llvm/prebuilt/*/bin/{exe_name}"))

    for sdk in _sdk_roots():
        ndk_root = sdk / "ndk"
        if ndk_root.is_dir():
            for sub in sorted(ndk_root.iterdir(), reverse=True):
                candidates.extend(sub.glob(f"toolchains/llvm/prebuilt/*/bin/{exe_name}"))

    return find_first_existing(candidates, f"Android NDK {exe_name}")


def find_android_jar() -> pathlib.Path:
    candidates: List[pathlib.Path] = []
    for sdk in _sdk_roots():
        platforms = sdk / "platforms"
        if platforms.is_dir():
            for sub in sorted(platforms.iterdir(), reverse=True):
                jar = sub / "android.jar"
                if jar.is_file():
                    candidates.append(jar)
    return find_first_existing(candidates, "android.jar")


def find_build_tool(base_name: str, win_ext: str = ".exe") -> pathlib.Path:
    tool_name = f"{base_name}{win_ext}" if IS_WINDOWS else base_name
    which_hit = shutil.which(tool_name) or shutil.which(base_name)
    if which_hit:
        return pathlib.Path(which_hit)

    candidates: List[pathlib.Path] = []
    for sdk in _sdk_roots():
        bt_root = sdk / "build-tools"
        if bt_root.is_dir():
            for sub in sorted(bt_root.iterdir(), reverse=True):
                candidates.append(sub / tool_name)
    return find_first_existing(candidates, tool_name)


def find_aapt2() -> pathlib.Path:
    return find_build_tool("aapt2", ".exe")


def find_d8() -> pathlib.Path:
    return find_build_tool("d8", ".bat")


def find_zipalign() -> pathlib.Path:
    return find_build_tool("zipalign", ".exe")


def find_apksigner() -> pathlib.Path:
    candidates: List[pathlib.Path] = []
    for sdk in _sdk_roots():
        bt_root = sdk / "build-tools"
        if bt_root.is_dir():
            for sub in sorted(bt_root.iterdir(), reverse=True):
                candidates.append(sub / "lib" / "apksigner.jar")
    return find_first_existing(candidates, "apksigner.jar")


def find_apktool_jar() -> pathlib.Path:
    env_jar = os.environ.get("APKTOOL_JAR", "").strip()
    candidates: List[pathlib.Path] = []
    if env_jar:
        candidates.append(pathlib.Path(env_jar))
    candidates.append(ROOT / "tools" / "apktool.jar")
    return find_first_existing(candidates, "apktool.jar (set APKTOOL_JAR or place in tools/apktool.jar)")


def find_frida_gadget() -> Optional[pathlib.Path]:
    env_so = os.environ.get("FRIDA_GADGET_SO", "").strip()
    candidates: List[pathlib.Path] = []
    if env_so:
        candidates.append(pathlib.Path(env_so))
    candidates.append(ROOT / "prebuilt" / "arm64-v8a" / "libfrida-gadget.so")
    for p in candidates:
        if p.is_file():
            return p
    return None


def ensure_keystore(keystore_path: pathlib.Path = DEFAULT_KS) -> pathlib.Path:
    if keystore_path.is_file():
        return keystore_path
    keystore_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore",
            str(keystore_path),
            "-storepass",
            DEFAULT_KS_PASS,
            "-keypass",
            DEFAULT_KS_PASS,
            "-alias",
            DEFAULT_KS_ALIAS,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Bridger Debug,O=Bridger,C=US",
        ],
        check=True,
    )
    return keystore_path


def compile_native_binaries() -> Dict[str, pathlib.Path]:
    clang = find_ndk_clang()
    DIST_BIN_DIR.mkdir(parents=True, exist_ok=True)

    libbridger_so = DIST_BIN_DIR / "libbridger.so"
    memtool_bin = DIST_BIN_DIR / "bridger_memtool"
    ptrace_bp_bin = DIST_BIN_DIR / "bridger_ptrace_bp"

    target_triple = "aarch64-linux-android24"

    print(f"[1/3] Compiling native arm64 binaries with {clang.name}...")
    subprocess.run(
        [
            str(clang),
            "-target",
            target_triple,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wno-unused-parameter",
            str(SRC_NATIVE / "bridger_jni.c"),
            "-llog",
            "-o",
            str(libbridger_so),
        ],
        check=True,
    )

    subprocess.run(
        [
            str(clang),
            "-target",
            target_triple,
            "-fPIE",
            "-pie",
            "-O2",
            "-Wall",
            "-Wextra",
            str(SRC_NATIVE / "bridger_memtool.c"),
            "-o",
            str(memtool_bin),
        ],
        check=True,
    )

    subprocess.run(
        [
            str(clang),
            "-target",
            target_triple,
            "-fPIE",
            "-pie",
            "-O2",
            "-Wall",
            "-Wextra",
            str(SRC_NATIVE / "bridger_ptrace_bp.c"),
            "-ldl",
            "-o",
            str(ptrace_bp_bin),
        ],
        check=True,
    )

    return {
        "libbridger.so": libbridger_so,
        "bridger_memtool": memtool_bin,
        "bridger_ptrace_bp": ptrace_bp_bin,
    }


def compile_java_to_dex(work_dir: pathlib.Path) -> pathlib.Path:
    android_jar = find_android_jar()
    d8_tool = find_d8()

    classes_dir = work_dir / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)

    java_files = sorted(str(p) for p in SRC_JAVA.rglob("*.java"))
    if not java_files:
        raise RuntimeError(f"No Java sources found under {SRC_JAVA}")

    print(f"[2/3] Compiling {len(java_files)} Java source files -> classes.dex...")
    subprocess.run(
        [
            "javac",
            "-source",
            "1.8",
            "-target",
            "1.8",
            "-encoding",
            "UTF-8",
            "-classpath",
            str(android_jar),
            "-d",
            str(classes_dir),
            *java_files,
        ],
        check=True,
    )

    class_files = sorted(str(p) for p in classes_dir.rglob("*.class"))
    dex_out_dir = work_dir / "dex"
    dex_out_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            str(d8_tool),
            "--min-api",
            "23",
            "--lib",
            str(android_jar),
            "--output",
            str(dex_out_dir),
            *class_files,
        ],
        check=True,
    )
    dex_file = dex_out_dir / "classes.dex"
    if not dex_file.is_file():
        raise RuntimeError("d8 did not produce classes.dex")
    return dex_file


def render_manifest(
    dest_manifest: pathlib.Path,
    package_name: str,
    shared_uid: str,
    app_name: str,
) -> None:
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(SRC_MANIFEST)
    root = tree.getroot()
    root.set("package", package_name)
    if shared_uid:
        root.set(f"{{{ANDROID_NS}}}sharedUserId", shared_uid)
    elif f"{{{ANDROID_NS}}}sharedUserId" in root.attrib:
        del root.attrib[f"{{{ANDROID_NS}}}sharedUserId"]

    app_el = root.find("application")
    if app_el is not None and app_name:
        app_el.set(f"{{{ANDROID_NS}}}label", app_name)

    tree.write(dest_manifest, encoding="utf-8", xml_declaration=True)


def zipalign_apk(zipalign: pathlib.Path, in_apk: pathlib.Path, out_apk: pathlib.Path) -> None:
    subprocess.run(
        [str(zipalign), "-p", "-f", "4", str(in_apk), str(out_apk)],
        check=True,
    )


def sign_apk(
    apksigner_jar: pathlib.Path,
    apk_path: pathlib.Path,
    keystore: pathlib.Path,
    ks_pass: str = DEFAULT_KS_PASS,
    ks_alias: str = DEFAULT_KS_ALIAS,
) -> None:
    subprocess.run(
        [
            "java",
            "-jar",
            str(apksigner_jar),
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            f"pass:{ks_pass}",
            "--key-pass",
            f"pass:{ks_pass}",
            "--ks-key-alias",
            ks_alias,
            str(apk_path),
        ],
        check=True,
    )
    idsig = apk_path.with_suffix(apk_path.suffix + ".idsig")
    if idsig.exists():
        idsig.unlink()


def package_apk_variant(
    work_dir: pathlib.Path,
    dex_file: pathlib.Path,
    native_bins: Dict[str, pathlib.Path],
    output_apk: pathlib.Path,
    package_name: str,
    shared_uid: str,
    app_name: str,
    include_gadget: bool,
    sign: bool = False,
    keystore: Optional[pathlib.Path] = None,
    ks_pass: str = DEFAULT_KS_PASS,
    ks_alias: str = DEFAULT_KS_ALIAS,
) -> pathlib.Path:
    aapt2 = find_aapt2()
    android_jar = find_android_jar()
    zipalign = find_zipalign()

    variant_dir = work_dir / f"variant_{package_name}_{'gadget' if include_gadget else 'std'}"
    variant_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = variant_dir / "AndroidManifest.xml"
    render_manifest(manifest_path, package_name=package_name, shared_uid=shared_uid, app_name=app_name)

    compiled_res_zip = variant_dir / "compiled_res.zip"
    subprocess.run(
        [
            str(aapt2),
            "compile",
            "--dir",
            str(SRC_RES),
            "-o",
            str(compiled_res_zip),
        ],
        check=True,
    )

    base_res_apk = variant_dir / "base_res.apk"
    subprocess.run(
        [
            str(aapt2),
            "link",
            "-I",
            str(android_jar),
            "--manifest",
            str(manifest_path),
            "-o",
            str(base_res_apk),
            str(compiled_res_zip),
        ],
        check=True,
    )

    unaligned_apk = variant_dir / "unaligned.apk"
    shutil.copy2(base_res_apk, unaligned_apk)

    with zipfile.ZipFile(unaligned_apk, "a") as zf:
        zf.write(dex_file, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
        # Store native .so files uncompressed (ZIP_STORED) for 4KB page alignment
        zf.write(native_bins["libbridger.so"], "lib/arm64-v8a/libbridger.so", compress_type=zipfile.ZIP_STORED)
        zf.write(native_bins["bridger_memtool"], "lib/arm64-v8a/libbridger_memtool.so", compress_type=zipfile.ZIP_STORED)
        zf.write(native_bins["bridger_ptrace_bp"], "lib/arm64-v8a/libbridger_ptrace_bp.so", compress_type=zipfile.ZIP_STORED)

        if include_gadget:
            gadget_so = find_frida_gadget()
            if gadget_so is None:
                raise FileNotFoundError(
                    "Frida gadget binary not found. Set FRIDA_GADGET_SO or place in prebuilt/arm64-v8a/libfrida-gadget.so"
                )
            zf.write(gadget_so, "lib/arm64-v8a/libfrida-gadget.so", compress_type=zipfile.ZIP_STORED)
            zf.write(GADGET_CFG, "lib/arm64-v8a/libfrida-gadget.config.so", compress_type=zipfile.ZIP_STORED)

    aligned_apk = variant_dir / "aligned.apk"
    zipalign_apk(zipalign, unaligned_apk, aligned_apk)

    output_apk.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(aligned_apk, output_apk)

    if sign:
        ks = ensure_keystore(keystore or DEFAULT_KS)
        apksigner = find_apksigner()
        sign_apk(apksigner, output_apk, ks, ks_pass=ks_pass, ks_alias=ks_alias)

    return output_apk


def build_bridger(
    package_name: str = "io.bridger",
    shared_uid: str = "io.bridger.shared",
    app_name: str = "Bridger",
    prefix: str = "bridger",
    with_gadget: bool = False,
    sign: bool = False,
    keystore: Optional[pathlib.Path] = None,
    ks_pass: str = DEFAULT_KS_PASS,
    ks_alias: str = DEFAULT_KS_ALIAS,
) -> List[pathlib.Path]:
    native_bins = compile_native_binaries()
    built_apks: List[pathlib.Path] = []
    suffix = "signed" if sign else "unsigned"

    with tempfile.TemporaryDirectory(prefix="bridger_build_") as tmp:
        work_dir = pathlib.Path(tmp)
        dex_file = compile_java_to_dex(work_dir)

        std_apk = DIST_DIR / f"{prefix}_{suffix}.apk"
        print(f"[3/3] Packaging {std_apk.name} (pkg={package_name}, sharedUserId={shared_uid})...")
        package_apk_variant(
            work_dir=work_dir,
            dex_file=dex_file,
            native_bins=native_bins,
            output_apk=std_apk,
            package_name=package_name,
            shared_uid=shared_uid,
            app_name=app_name,
            include_gadget=False,
            sign=sign,
            keystore=keystore,
            ks_pass=ks_pass,
            ks_alias=ks_alias,
        )
        built_apks.append(std_apk)

        if with_gadget:
            gadget_apk = DIST_DIR / f"{prefix}_gadget_{suffix}.apk"
            print(f"[+] Packaging {gadget_apk.name} (with Frida Gadget)...")
            package_apk_variant(
                work_dir=work_dir,
                dex_file=dex_file,
                native_bins=native_bins,
                output_apk=gadget_apk,
                package_name=package_name,
                shared_uid=shared_uid,
                app_name=f"{app_name} (Gadget)",
                include_gadget=True,
                sign=sign,
                keystore=keystore,
                ks_pass=ks_pass,
                ks_alias=ks_alias,
            )
            built_apks.append(gadget_apk)

    return built_apks


def main() -> int:
    ap = argparse.ArgumentParser(description="Build Bridger APKs and native arm64 tools from source")
    ap.add_argument("--package", default="io.bridger", help="Android package name (default: io.bridger)")
    ap.add_argument("--shared-uid", default="io.bridger.shared", help="android:sharedUserId value (default: io.bridger.shared)")
    ap.add_argument("--app-name", default="Bridger", help="Launcher display label")
    ap.add_argument("--prefix", default="bridger", help="Output APK filename prefix in dist/")
    ap.add_argument("--with-gadget", action="store_true", help="Also build Frida Gadget APK variant")
    ap.add_argument("--sign", action="store_true", help="Sign output APKs (generates local keystore/debug.keystore if --keystore not given)")
    ap.add_argument("--keystore", default="", help="Custom keystore path for --sign")
    ap.add_argument("--ks-pass", default=DEFAULT_KS_PASS, help="Keystore password")
    ap.add_argument("--ks-alias", default=DEFAULT_KS_ALIAS, help="Keystore key alias")
    args = ap.parse_args()

    ks_path = pathlib.Path(args.keystore).resolve() if args.keystore else None
    outputs = build_bridger(
        package_name=args.package,
        shared_uid=args.shared_uid,
        app_name=args.app_name,
        prefix=args.prefix,
        with_gadget=args.with_gadget,
        sign=args.sign,
        keystore=ks_path,
        ks_pass=args.ks_pass,
        ks_alias=args.ks_alias,
    )

    print("\n[+] Build Summary:")
    for bin_file in sorted(DIST_BIN_DIR.glob("*")):
        print(f"    Native : {bin_file.relative_to(ROOT)} ({bin_file.stat().st_size:,} bytes)")
    for apk in outputs:
        print(f"    APK    : {apk.relative_to(ROOT)} ({apk.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
