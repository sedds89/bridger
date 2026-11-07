'use strict';

/**
 * Bridger Generic Frida Runtime (`client/frida/bridger_runtime.js`)
 *
 * Attach to Bridger's Frida Gadget on 127.0.0.1:27043 (or any same-UID process)
 * and call `rpc.exports.*` for any target package.
 *
 * Key design points:
 *  1. Target-agnostic: every method accepts `targetPkg` or `pid` for any same-UID target process.
 *  2. Untruncated `/proc/<pid>/maps`: reads via buffered `fopen` + `fgets` (or `BridgerEngine`)
 *     instead of 4KB-truncated `pread` on seq_file.
 *  3. Delegates to `io.bridger.BridgerEngine` / `libbridger.so` when loaded inside Bridger,
 *     automatically gaining `PTRACE_SEIZE` + `PTRACE_INTERRUPT` cross-process memory writes.
 */

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_RDWR = 2;
const O_CREAT = 0x40;
const O_TRUNC = 0x200;

function cfunc(name, ret, args) {
    const p = Module.findExportByName('libc.so', name);
    if (!p) throw new Error('libc export missing: ' + name);
    return new NativeFunction(p, ret, args);
}

const _open = cfunc('open', 'int', ['pointer', 'int', 'int']);
const _close = cfunc('close', 'int', ['int']);
const _read = cfunc('read', 'ssize_t', ['int', 'pointer', 'size_t']);
const _write = cfunc('write', 'ssize_t', ['int', 'pointer', 'size_t']);
const _pread64 = cfunc('pread64', 'ssize_t', ['int', 'pointer', 'size_t', 'int64']);
const _pwrite64 = cfunc('pwrite64', 'ssize_t', ['int', 'pointer', 'size_t', 'int64']);
const _fopen = cfunc('fopen', 'pointer', ['pointer', 'pointer']);
const _fgets = cfunc('fgets', 'pointer', ['pointer', 'int', 'pointer']);
const _fclose = cfunc('fclose', 'int', ['pointer']);
const _getpid = cfunc('getpid', 'int', []);
const _getuid = cfunc('getuid', 'int', []);
const _chmod = cfunc('chmod', 'int', ['pointer', 'int']);
const _mkdir = cfunc('mkdir', 'int', ['pointer', 'int']);
const _unlink = cfunc('unlink', 'int', ['pointer']);
const _opendir = cfunc('opendir', 'pointer', ['pointer']);
const _readdir = cfunc('readdir', 'pointer', ['pointer']);
const _closedir = cfunc('closedir', 'int', ['pointer']);
const _errno = cfunc('__errno', 'pointer', []);

function lastErrno() {
    return _errno().readS32();
}

function readSmallFile(path, maxBytes) {
    const fd = _open(Memory.allocUtf8String(path), O_RDONLY, 0);
    if (fd < 0) return null;
    const cap = maxBytes || 65536;
    const buf = Memory.alloc(cap);
    let total = 0;
    while (total < cap) {
        const n = _read(fd, buf.add(total), cap - total);
        if (n <= 0) break;
        total += n.toNumber ? n.toNumber() : n;
    }
    _close(fd);
    return buf.readByteArray(total);
}

function readTextLines(path) {
    const fp = _fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
    if (fp.isNull()) return null;
    const lineBuf = Memory.alloc(1024);
    const lines = [];
    while (!_fgets(lineBuf, 1024, fp).isNull()) {
        lines.push(lineBuf.readUtf8String());
    }
    _fclose(fp);
    return lines;
}

function listDirRaw(path) {
    const dir = _opendir(Memory.allocUtf8String(path));
    if (dir.isNull()) return { ok: false, errno: lastErrno(), path: path };
    const names = [];
    while (true) {
        const ent = _readdir(dir);
        if (ent.isNull()) break;
        const dtype = ent.add(18).readU8();
        const name = ent.add(19).readUtf8String();
        if (name !== '.' && name !== '..') {
            names.push({ name: name, type: dtype });
        }
    }
    _closedir(dir);
    return { ok: true, path: path, entries: names };
}

function findPidByNameRaw(pkgName) {
    const proc = listDirRaw('/proc');
    if (!proc.ok) return -1;
    const myPid = _getpid();
    for (const e of proc.entries) {
        if (!/^\d+$/.test(e.name)) continue;
        const pid = parseInt(e.name, 10);
        if (pid === myPid) continue;
        const raw = readSmallFile('/proc/' + pid + '/cmdline', 256);
        if (!raw) continue;
        const u8 = new Uint8Array(raw);
        let end = u8.indexOf(0);
        if (end < 0) end = u8.length;
        let s = '';
        for (let i = 0; i < end; i++) s += String.fromCharCode(u8[i]);
        if (s === pkgName) return pid;
    }
    return -1;
}

function callBridgerEngine(reqObj) {
    return new Promise((resolve, reject) => {
        if (!Java.available) {
            reject(new Error('Java runtime not available'));
            return;
        }
        Java.perform(() => {
            try {
                const ActivityThread = Java.use('android.app.ActivityThread');
                const app = ActivityThread.currentApplication();
                const ctx = app ? app.getApplicationContext() : null;
                const JSONObject = Java.use('org.json.JSONObject');
                const BridgerEngine = Java.use('io.bridger.BridgerEngine');
                const req = JSONObject.$new(JSON.stringify(reqObj));
                const resp = BridgerEngine.execute(ctx, req);
                resolve(JSON.parse(resp.toString()));
            } catch (e) {
                reject(e);
            }
        });
    });
}

rpc.exports = {
    ping: function () {
        return {
            ok: true,
            pid: _getpid(),
            uid: _getuid(),
            arch: Process.arch,
            platform: Process.platform
        };
    },

    engine: function (reqObj) {
        return callBridgerEngine(reqObj);
    },

    findPid: function (targetPkg) {
        if (!targetPkg) return -1;
        return findPidByNameRaw(String(targetPkg));
    },

    ls: function (path) {
        return listDirRaw(path);
    },

    maps: function (pidOrPkg, filterSubstr) {
        const pid = typeof pidOrPkg === 'number' ? pidOrPkg : findPidByNameRaw(String(pidOrPkg));
        if (pid <= 0) return { ok: false, error: 'process_not_found', target: pidOrPkg };
        const lines = readTextLines('/proc/' + pid + '/maps');
        if (!lines) return { ok: false, errno: lastErrno(), pid: pid };
        const out = [];
        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line) continue;
            if (filterSubstr && line.indexOf(filterSubstr) < 0) continue;
            out.push(line);
        }
        return { ok: true, pid: pid, count: out.length, lines: out };
    },

    memRead: function (pid, addrHex, size) {
        const fd = _open(Memory.allocUtf8String('/proc/' + pid + '/mem'), O_RDONLY, 0);
        if (fd < 0) return { ok: false, errno: lastErrno() };
        const buf = Memory.alloc(size);
        const offset = int64(addrHex.toString());
        const n = _pread64(fd, buf, size, offset);
        const err = lastErrno();
        _close(fd);
        const nNum = n.toNumber ? n.toNumber() : n;
        if (nNum < 0) return { ok: false, errno: err };
        const bytes = new Uint8Array(buf.readByteArray(nNum));
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            hex += ('0' + bytes[i].toString(16)).slice(-2);
        }
        return { ok: true, n: nNum, hex: hex };
    },

    memWrite: function (pid, addrHex, hexBytes) {
        return callBridgerEngine({
            cmd: 'mem.write',
            pid: pid,
            address: String(addrHex),
            hex: hexBytes
        }).catch(() => {
            const fd = _open(Memory.allocUtf8String('/proc/' + pid + '/mem'), O_RDWR, 0);
            if (fd < 0) return { ok: false, step: 'open', errno: lastErrno() };
            const len = hexBytes.length / 2;
            const buf = Memory.alloc(len);
            for (let i = 0; i < len; i++) {
                buf.add(i).writeU8(parseInt(hexBytes.substr(i * 2, 2), 16));
            }
            const offset = int64(addrHex.toString());
            const n = _pwrite64(fd, buf, len, offset);
            const err = lastErrno();
            _close(fd);
            const nNum = n.toNumber ? n.toNumber() : n;
            if (nNum < 0) return { ok: false, step: 'pwrite64', errno: err };
            return { ok: true, written: nNum };
        });
    },

    redirect: function (pidOrPkg, fromStr, toStr) {
        const req = {
            cmd: 'mem.redirect',
            from: fromStr,
            to: toStr
        };
        if (typeof pidOrPkg === 'number') req.pid = pidOrPkg;
        else req.target_pkg = String(pidOrPkg);
        return callBridgerEngine(req);
    },

    copyFile: function (srcPath, dstPath, mode) {
        const sfd = _open(Memory.allocUtf8String(srcPath), O_RDONLY, 0);
        if (sfd < 0) return { ok: false, where: 'open_src', errno: lastErrno(), path: srcPath };
        const dfd = _open(Memory.allocUtf8String(dstPath), O_WRONLY | O_CREAT | O_TRUNC, mode || 0o755);
        if (dfd < 0) {
            const e = lastErrno();
            _close(sfd);
            return { ok: false, where: 'open_dst', errno: e, path: dstPath };
        }
        const chunk = Memory.alloc(65536);
        let total = 0;
        while (true) {
            const n = _read(sfd, chunk, 65536);
            const nNum = n.toNumber ? n.toNumber() : n;
            if (nNum <= 0) break;
            const w = _write(dfd, chunk, nNum);
            const wNum = w.toNumber ? w.toNumber() : w;
            if (wNum < 0) {
                const e = lastErrno();
                _close(sfd);
                _close(dfd);
                return { ok: false, where: 'write', errno: e, total: total };
            }
            total += wNum;
        }
        _close(sfd);
        _close(dfd);
        if (mode) _chmod(Memory.allocUtf8String(dstPath), mode);
        return { ok: true, bytes: total, src: srcPath, dst: dstPath };
    },

    chmod: function (path, mode) {
        const r = _chmod(Memory.allocUtf8String(path), mode);
        return { ok: r === 0, errno: r === 0 ? 0 : lastErrno() };
    },

    mkdir: function (path, mode) {
        const r = _mkdir(Memory.allocUtf8String(path), mode || 0o755);
        return { ok: r === 0, errno: r === 0 ? 0 : lastErrno() };
    },

    unlink: function (path) {
        const r = _unlink(Memory.allocUtf8String(path));
        return { ok: r === 0, errno: r === 0 ? 0 : lastErrno() };
    }
};
