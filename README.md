# Bridger — Zero-Crash Cross-Process Android Bridge

**Bridger** is a companion Android APK, C11 JNI engine (`libbridger.so`), standalone `arm64-v8a` memory/ptrace toolkit, and Python/Frida client that lets you inspect, patch, and instrument a target Android application **without injecting into or crashing the target APK**.

---

## Why Bridger? (Hook with Frida via Gadget, Root, or PRoot Without Crashing the Target App)

Injecting `libfrida-gadget.so` directly into a target APK—or attaching `frida-server` (via root or PRoot) directly to a target process—often causes the target app to crash or exit immediately because:
- The target app scans `/proc/self/maps` or `/proc/self/task/*/comm` for `frida`, `gadget`, `gum-js-loop`, or `gmain`.
- The target app verifies its own DEX/SO checksums or detects inline hooks in `libc.so` / `libart.so`.
- Attaching a full Frida agent to a heavy multi-threaded app (200+ threads) causes `ptrace` group-stop stalls or watchdog timeouts.

### How Bridger Solves This
1. **Shared Signature + Shared Linux UID (`android:sharedUserId`)**:
   You sign both the target APK and the **Bridger** APK with the **same signing key** and matching `android:sharedUserId`. Android assigns both apps the **exact same Linux kernel UID**.
2. **Frida & Native Tooling Run Inside Bridger — Not the Target App**:
   Whether you use **Frida Gadget** bundled inside Bridger, or attach Frida via **root / PRoot** to the `io.bridger` process, Frida lives strictly inside the lightweight `io.bridger` process.
   - The target app's `/proc/<target_pid>/maps`, threads, and code pages remain **100% clean of Frida**.
   - From inside `io.bridger`, your Frida scripts (or Bridger's built-in TCP JSON-RPC server) have full same-UID kernel permissions to read/write `/proc/<target_pid>/mem`, read `/proc/<target_pid>/maps`, and access `/data/data/<target_pkg>/` without crashing the target APK.

```text
+--------------------------------------+          Same Linux UID           +--------------------------------------+
|         Bridger (io.bridger)         |  <=============================>  |     Target App (com.example.app)     |
|                                      |   sharedUserId + Same Signature   |                                      |
| - Runs Frida (Gadget / Root / PRoot) |                                   | - NO Frida injected into process     |
| - Runs libbridger.so + TCP RPC :27044|  --- /proc/<pid>/mem (R/W) ---->  | - Clean /proc/self/maps & threads    |
| - Never crashes target app           |  --- /proc/<pid>/maps (Read) -->  | - Zero anti-Frida / hook crashes     |
|                                      |  --- /data/data/<pkg> (R/W) --->  |                                      |
+--------------------------------------+                                   +--------------------------------------+
```

---

## Key Features

- **Same-Signature Target APK Pairer (`pair_target_apk.py`)**:
  Automatically patches a target APK's `AndroidManifest.xml` (without decompiling DEX files) to add `android:sharedUserId` and signs both the target APK and Bridger with the exact same keystore.
- **Persistent Foreground Service (`BridgerService` + `BridgerActivity`)**:
  Runs a sticky foreground service hosting a local TCP JSON-RPC server on `127.0.0.1:27044` so Android's cached-process / LMK killer never kills the bridge in the background. Supports headless launch (`--ez headless true`).
- **Untruncated `/proc/<pid>/maps` Reader (`libbridger.so`)**:
  Reads process memory mappings via native buffered `fopen` + `fgets` (avoiding the 4 KB `seq_file` truncation limit when reading `/proc/<pid>/maps` from Frida `pread`) with server-side filters for permissions (`perm`), path substrings (`path`), and minimum size (`min_size`).
- **Cross-Process `/proc/<pid>/mem` Read, Write, Scan & Live String Redirection**:
  - Scans target memory regions for ASCII, UTF-16LE, or raw hex byte patterns.
  - Writes to `/proc/<pid>/mem` with automatic single-thread `PTRACE_SEIZE` + `PTRACE_INTERRUPT` fallback on kernels that require an active tracer for cross-process memory writes (avoiding multi-thread `PTRACE_ATTACH` hangs).
  - Redirects ASCII and UTF-16LE strings/URLs in-place across writable regions (`rw-p`) and Unity IL2CPP `global-metadata.dat` mappings.
- **Private App Data Filesystem Operations (`/data/data/<target_pkg>`)**:
  List (`fs.ls`), stat (`fs.stat`), copy (`fs.copy`), feed (`fs.feed`), pull (`fs.pull`), mkdir (`fs.mkdir`), delete (`fs.rm`), and read/write text files inside any paired target package.
- **Android 10+ SELinux `W^X` Compatible Native Binaries**:
  Compiles standalone `arm64-v8a` CLI binaries (`bridger_memtool` and `bridger_ptrace_bp`) and bundles them inside `lib/arm64-v8a/` (`libbridger_memtool.so`, `libbridger_ptrace_bp.so`) so they can be executed directly from the SELinux-sanctioned native library directory.

---

## Repository Structure

```text
Bridger/
├── build_bridger.py                 # Source build script (NDK clang + javac + d8 + aapt2 + zipalign + apksigner)
├── pair_target_apk.py               # Patches target APK with matching sharedUserId & signs with same key
├── LICENSE                          # MIT License
├── src/
│   ├── main/
│   │   ├── AndroidManifest.xml      # App manifest template
│   │   ├── res/values/strings.xml
│   │   └── java/io/bridger/
│   │       ├── BridgerActivity.java # Live status dashboard UI + headless launcher
│   │       ├── BridgerService.java  # Sticky Foreground Service + TCP JSON-RPC server (:27044)
│   │       ├── BridgerReceiver.java # Broadcast receiver (io.bridger.COMMAND / io.bridger.FEED)
│   │       ├── BridgerEngine.java   # Command processor (fs.*, mem.*, maps, pidof, intent.*, exec)
│   │       └── BridgerNative.java   # JNI bindings for libbridger.so & optional libfrida-gadget.so
│   └── native/
│       ├── bridger_jni.c            # JNI library (libbridger.so): maps, mem read/write/scan/redirect + PTRACE_SEIZE
│       ├── bridger_memtool.c        # Standalone arm64 CLI: pidof, maps, find (--u16), dump, poke, redir
│       └── bridger_ptrace_bp.c      # Standalone arm64 multi-thread PTRACE_SEIZE breakpoint & register logger
└── client/
    ├── bridger_cli.py               # Python CLI & SDK (TCP :27044, ADB Broadcast, or Frida :27043)
    └── frida/
        ├── bridger_runtime.js       # Target-agnostic Frida RPC script
        └── gadget.config.json       # Frida Gadget listen config (127.0.0.1:27043)
```

---

## Step 1: Build Bridger & Sign Target App with the Same Signature

Both Bridger and your target APK **must** share:
1. The same `android:sharedUserId` (default: `io.bridger.shared`).
2. The exact same signing certificate (`keystore/debug.keystore` or your own `--keystore`).

### 1. Build & Sign Bridger
```bash
# Compiles native arm64 binaries + Java DEX and signs dist/bridger_signed.apk
# (Automatically generates keystore/debug.keystore if it does not exist yet)
python build_bridger.py --sign

# Optional: also build dist/bridger_gadget_signed.apk with Frida Gadget bundled
export FRIDA_GADGET_SO=/path/to/libfrida-gadget-android-arm64.so
python build_bridger.py --with-gadget --sign
```

### 2. Patch & Sign Your Target APK with the Same Signature
```bash
export APKTOOL_JAR=/path/to/apktool.jar

# Injects android:sharedUserId="io.bridger.shared" into target.apk's manifest
# and signs it with the exact same keystore (keystore/debug.keystore)
python pair_target_apk.py \
  --in target.apk \
  --out dist/target_paired.apk \
  --shared-uid io.bridger.shared \
  --sign

# Install both APKs (uninstall any previous store-signed version of the target app first)
adb install -r dist/target_paired.apk
adb install -r dist/bridger_signed.apk
```

---

## Step 2: Hook with Frida (Root, PRoot, or Gadget) Without Crashing the Target APK

Because `io.bridger` shares the target app's UID, **always attach Frida to `io.bridger` (or `Gadget`), never directly to the target app**:

### Option A: Using Root / PRoot `frida-server`
Attach Frida to the `io.bridger` process on the device and load `client/frida/bridger_runtime.js`:
```bash
# Wake Bridger in the background
adb shell am start -n io.bridger/io.bridger.BridgerActivity --ez headless true

# Attach Frida to io.bridger instead of the target app — target APK will NEVER crash!
frida -U -n io.bridger -l client/frida/bridger_runtime.js
```

### Option B: Using Bundled Frida Gadget (Rootless / Non-Root Devices)
If you installed `dist/bridger_gadget_signed.apk`, Bridger listens on `127.0.0.1:27043`:
```bash
adb forward tcp:27043 tcp:27043
frida -H 127.0.0.1:27043 -n Gadget -l client/frida/bridger_runtime.js
```

Inside the Frida REPL (or via `script.exports_sync` in Python), interact with the target process safely across processes:
```javascript
// Find target PID without touching the target process with Frida agent
const pid = rpc.exports.findPid("com.example.app");

// Read untruncated /proc/<pid>/maps
const maps = rpc.exports.maps("com.example.app", "rw-p");

// Read / write target process memory (auto PTRACE_SEIZE fallback via BridgerEngine)
rpc.exports.memRead(pid, "0x7a00001000", 64);
rpc.exports.memWrite(pid, "0x7a00001000", "90909090");

// Live in-memory ASCII + UTF-16LE URL/string redirect across rw-p & global-metadata.dat
rpc.exports.redirect("com.example.app", "https://api.example.com", "http://10.0.2.2:8080/v1");
```

---

## Step 3: Using the Python CLI (`client/bridger_cli.py`)

You can also perform all cross-process memory and file operations directly over Bridger's built-in TCP JSON-RPC server (`127.0.0.1:27044`) or ADB Broadcasts (`--transport broadcast`) or Frida (`--transport frida`):

```bash
# 1. Check Bridger status and verify shared-UID access to your target package:
python client/bridger_cli.py status --target com.example.app

# 2. Find live PID of the target package:
python client/bridger_cli.py pidof com.example.app

# 3. Read untruncated /proc/<pid>/maps (filtering by permission, path, or minimum size):
python client/bridger_cli.py maps --target com.example.app --perm rw-p --min-size 1048576

# 4. List or pull private files from /data/data/<target>:
python client/bridger_cli.py ls --target com.example.app --rel files
python client/bridger_cli.py pull --target com.example.app --src files/config.json --out ./config.json

# 5. Feed a file into the target package's private directory:
python client/bridger_cli.py feed payload.bin --target com.example.app --inbox-rel files/inbox

# 6. Scan target process memory (ASCII, UTF-16LE, or hex):
python client/bridger_cli.py scan --target com.example.app --pattern "api.example.com" --utf16

# 7. Live in-memory string/URL redirection (ASCII + UTF-16LE across rw-p + global-metadata.dat):
python client/bridger_cli.py redirect --target com.example.app \
  --pair "https://api.example.com=http://10.0.2.2:8080/v1"
```

---

## License

Released under the [MIT License](LICENSE).
