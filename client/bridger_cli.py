#!/usr/bin/env python3
"""
Bridger Python CLI & SDK (`client/bridger_cli.py`)

Communicates with the Bridger APK over:
  1. TCP JSON-RPC (`127.0.0.1:27044` via `adb forward tcp:27044 tcp:27044`) — fast, persistent, zero-Frida dependency
  2. ADB Broadcast (`io.bridger.COMMAND` -> `/sdcard/Download/bridger_last_result.json`) — works even before port forwarding
  3. Frida Gadget (`127.0.0.1:27043` with `client/frida/bridger_runtime.js`) — full dynamic instrumentation

Examples:
  python client/bridger_cli.py status --target com.example.app
  python client/bridger_cli.py pidof com.example.app
  python client/bridger_cli.py maps --target com.example.app --perm rw-p --min-size 1048576
  python client/bridger_cli.py ls --target com.example.app --rel files
  python client/bridger_cli.py feed payload.bin --target com.example.app
  python client/bridger_cli.py pull --target com.example.app --src files/config.json --out ./config.json
  python client/bridger_cli.py scan --target com.example.app --pattern "api.example.com" --utf16
  python client/bridger_cli.py redirect --target com.example.app \
      --pair "https://api.example.com=http://10.0.2.2:8080/v1"
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRIDA_SCRIPT = ROOT / "client" / "frida" / "bridger_runtime.js"
DEFAULT_RPC_PORT = 27044
DEFAULT_FRIDA_PORT = 27043


class BridgerClient:
    def __init__(
        self,
        bridge_pkg: str = "io.bridger",
        rpc_port: int = DEFAULT_RPC_PORT,
        frida_port: int = DEFAULT_FRIDA_PORT,
        serial: Optional[str] = None,
        transport: str = "auto",
    ) -> None:
        self.bridge_pkg = bridge_pkg
        self.rpc_port = rpc_port
        self.frida_port = frida_port
        self.serial = serial
        self.transport = transport

    def _adb_cmd(self, *args: str) -> List[str]:
        cmd = ["adb"]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(args)
        return cmd

    def adb(self, *args: str, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            self._adb_cmd(*args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def ensure_running(self, headless: bool = True) -> None:
        self.adb(
            "shell",
            "am",
            "start",
            "-n",
            f"{self.bridge_pkg}/io.bridger.BridgerActivity",
            "--ez",
            "headless",
            "true" if headless else "false",
            check=False,
        )
        self.adb("forward", f"tcp:{self.rpc_port}", f"tcp:{self.rpc_port}", check=False)

    def request_tcp(self, payload: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        with socket.create_connection(("127.0.0.1", self.rpc_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw)
            buf = bytearray()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\n" in chunk:
                    break
        line = buf.decode("utf-8", errors="replace").strip().splitlines()[0]
        return json.loads(line)

    def request_broadcast(self, payload: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
        req_id = payload.get("id") or f"req_{int(time.time() * 1000)}"
        payload = dict(payload, id=req_id)
        json_str = json.dumps(payload, separators=(",", ":"))
        self.adb(
            "shell",
            "am",
            "broadcast",
            "-n",
            f"{self.bridge_pkg}/io.bridger.BridgerReceiver",
            "-a",
            "io.bridger.COMMAND",
            "--es",
            "json",
            json_str,
            check=False,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.adb("shell", "cat", "/sdcard/Download/bridger_last_result.json", check=False)
            if res.returncode == 0 and res.stdout.strip():
                try:
                    parsed = json.loads(res.stdout.strip())
                    if parsed.get("id") == req_id:
                        return parsed
                except Exception:
                    pass
            time.sleep(0.25)
        raise TimeoutError(f"Timed out waiting for broadcast response id={req_id}")

    def request_frida(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        import frida  # type: ignore

        self.adb("forward", f"tcp:{self.frida_port}", f"tcp:{self.frida_port}", check=False)
        mgr = frida.get_device_manager()
        dev = mgr.add_remote_device(f"127.0.0.1:{self.frida_port}")
        sess = dev.attach("Gadget")
        sc = sess.create_script(FRIDA_SCRIPT.read_text(encoding="utf-8"))
        sc.load()
        try:
            return sc.exports_sync.engine(payload)
        finally:
            try:
                sc.unload()
                sess.detach()
            except Exception:
                pass

    def call(self, payload: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
        if self.transport == "tcp":
            return self.request_tcp(payload, timeout=timeout)
        if self.transport == "broadcast":
            return self.request_broadcast(payload, timeout=timeout)
        if self.transport == "frida":
            return self.request_frida(payload)

        # auto: try TCP first, wake service + forward on connection failure, then fallback to broadcast
        try:
            return self.request_tcp(payload, timeout=3.0)
        except Exception:
            self.ensure_running(headless=True)
            time.sleep(0.6)
            try:
                return self.request_tcp(payload, timeout=timeout)
            except Exception:
                return self.request_broadcast(payload, timeout=timeout)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bridger Cross-Process Android Bridge CLI")
    p.add_argument("--bridge-pkg", default=os.environ.get("BRIDGER_PKG", "io.bridger"), help="Installed Bridger package name (default: io.bridger)")
    p.add_argument("--port", type=int, default=DEFAULT_RPC_PORT, help="Bridger TCP JSON-RPC port (default: 27044)")
    p.add_argument("--serial", default=None, help="ADB device serial")
    p.add_argument("--transport", choices=["auto", "tcp", "broadcast", "frida"], default="auto", help="Transport mode")

    sub = p.add_subparsers(dest="subcmd", required=True)

    sp_status = sub.add_parser("status", help="Query Bridger status and optional target package readiness")
    sp_status.add_argument("--target", default="", help="Optional target package to inspect")

    sp_pid = sub.add_parser("pidof", help="Find live PID of a target package")
    sp_pid.add_argument("target", help="Target package/process name")

    sp_maps = sub.add_parser("maps", help="Read untruncated /proc/<pid>/maps for target")
    sp_maps.add_argument("--target", required=True, help="Target package name")
    sp_maps.add_argument("--perm", default="", help="Permission substring filter (e.g. rw-p)")
    sp_maps.add_argument("--path", default="", help="Path substring filter (e.g. global-metadata.dat)")
    sp_maps.add_argument("--min-size", type=int, default=0, help="Minimum region size in bytes")

    sp_ls = sub.add_parser("ls", help="List files inside /data/data/<target>/<rel>")
    sp_ls.add_argument("--target", default="", help="Target package name")
    sp_ls.add_argument("--rel", default="files", help="Relative path inside target data dir")
    sp_ls.add_argument("--path", default="", help="Explicit absolute path on device")

    sp_feed = sub.add_parser("feed", help="Push a local file and copy it into target package's private files/inbox")
    sp_feed.add_argument("local_file", help="Local file to push")
    sp_feed.add_argument("--target", required=True, help="Target package name")
    sp_feed.add_argument("--inbox-rel", default="files/inbox", help="Target relative directory")
    sp_feed.add_argument("--name", default="", help="Destination filename override")
    sp_feed.add_argument("--notify-action", default="", help="Optional broadcast action after copy")

    sp_pull = sub.add_parser("pull", help="Pull a private file from /data/data/<target>/<src> to local disk")
    sp_pull.add_argument("--target", default="", help="Target package name")
    sp_pull.add_argument("--src", required=True, help="Absolute path or relative path under /data/data/<target>")
    sp_pull.add_argument("--out", required=True, help="Local destination path")

    sp_scan = sub.add_parser("scan", help="Scan target process memory for ASCII, UTF-16LE, or hex pattern")
    sp_scan.add_argument("--target", required=True, help="Target package name")
    sp_scan.add_argument("--pattern", default="", help="String pattern to search")
    sp_scan.add_argument("--hex", default="", help="Hex byte pattern to search")
    sp_scan.add_argument("--utf16", action="store_true", help="Encode --pattern as UTF-16LE")
    sp_scan.add_argument("--perm", default="r", help="Permission filter (default: r)")
    sp_scan.add_argument("--path", default="", help="Region path substring filter")
    sp_scan.add_argument("--max-hits", type=int, default=100, help="Maximum hits to return")

    sp_read = sub.add_parser("mem-read", help="Read bytes from target process memory")
    sp_read.add_argument("--target", required=True, help="Target package name")
    sp_read.add_argument("--addr", required=True, help="Hex address (e.g. 0x7a00001000)")
    sp_read.add_argument("--len", type=int, default=64, help="Byte count")

    sp_poke = sub.add_parser("mem-write", help="Write bytes to target process memory (auto PTRACE_SEIZE fallback)")
    sp_poke.add_argument("--target", required=True, help="Target package name")
    sp_poke.add_argument("--addr", required=True, help="Hex address (e.g. 0x7a00001000)")
    sp_poke.add_argument("--hex", default="", help="Hex bytes to write")
    sp_poke.add_argument("--text", default="", help="Text string to write")
    sp_poke.add_argument("--utf16", action="store_true", help="Encode --text as UTF-16LE")

    sp_redir = sub.add_parser("redirect", help="Live in-memory ASCII + UTF-16LE string/URL redirector")
    sp_redir.add_argument("--target", required=True, help="Target package name")
    sp_redir.add_argument("--pair", action="append", required=True, help="Redirect pair in OLD=NEW format (can be repeated)")

    sp_exec = sub.add_parser("exec", help="Execute a shell command inside Bridger's shared UID context")
    sp_exec.add_argument("command", help="Command string to run")
    sp_exec.add_argument("--timeout", type=int, default=15, help="Timeout in seconds")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    client = BridgerClient(
        bridge_pkg=args.bridge_pkg,
        rpc_port=args.port,
        serial=args.serial,
        transport=args.transport,
    )

    if args.subcmd == "status":
        resp = client.call({"cmd": "status", "target_pkg": args.target})
    elif args.subcmd == "pidof":
        resp = client.call({"cmd": "pidof", "target_pkg": args.target})
    elif args.subcmd == "maps":
        resp = client.call(
            {
                "cmd": "maps",
                "target_pkg": args.target,
                "perm": args.perm,
                "path": args.path,
                "min_size": args.min_size,
            }
        )
    elif args.subcmd == "ls":
        resp = client.call(
            {
                "cmd": "fs.ls",
                "target_pkg": args.target,
                "rel_path": args.rel,
                "path": args.path,
            }
        )
    elif args.subcmd == "feed":
        local_path = pathlib.Path(args.local_file).resolve()
        if not local_path.is_file():
            print(f"Local file not found: {local_path}", file=sys.stderr)
            return 1
        staged_name = args.name or local_path.name
        staged_remote = f"/sdcard/Download/{staged_name}"
        client.adb("push", str(local_path), staged_remote)
        resp = client.call(
            {
                "cmd": "fs.feed",
                "src": staged_remote,
                "target_pkg": args.target,
                "inbox_rel": args.inbox_rel,
                "name": staged_name,
                "notify_action": args.notify_action,
            }
        )
    elif args.subcmd == "pull":
        src = args.src
        if args.target and not src.startswith("/"):
            src = f"/data/data/{args.target}/{src}"
        resp = client.call({"cmd": "fs.pull", "src": src})
        if resp.get("ok") and "data_b64" in resp:
            out_path = pathlib.Path(args.out).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            raw = base64.b64decode(resp.pop("data_b64"))
            out_path.write_bytes(raw)
            resp["saved_to"] = str(out_path)
    elif args.subcmd == "scan":
        req: Dict[str, Any] = {
            "cmd": "mem.scan",
            "target_pkg": args.target,
            "perm": args.perm,
            "path": args.path,
            "max_hits": args.max_hits,
        }
        if args.hex:
            req["hex"] = args.hex
        else:
            req["pattern"] = args.pattern
            req["utf16"] = args.utf16
        resp = client.call(req, timeout=30.0)
    elif args.subcmd == "mem-read":
        resp = client.call(
            {
                "cmd": "mem.read",
                "target_pkg": args.target,
                "address": args.addr,
                "length": args.len,
            }
        )
    elif args.subcmd == "mem-write":
        req = {
            "cmd": "mem.write",
            "target_pkg": args.target,
            "address": args.addr,
        }
        if args.hex:
            req["hex"] = args.hex
        else:
            req["text"] = args.text
            req["utf16"] = args.utf16
        resp = client.call(req)
    elif args.subcmd == "redirect":
        pairs = []
        for item in args.pair:
            if "=" not in item:
                print(f"Invalid --pair '{item}' (expected OLD=NEW)", file=sys.stderr)
                return 1
            old_s, new_s = item.split("=", 1)
            pairs.append({"from": old_s, "to": new_s})
        resp = client.call({"cmd": "mem.redirect", "target_pkg": args.target, "pairs": pairs}, timeout=45.0)
    elif args.subcmd == "exec":
        resp = client.call({"cmd": "exec", "command": args.command, "timeout_sec": args.timeout}, timeout=args.timeout + 5)
    else:
        parser.print_help()
        return 1

    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
