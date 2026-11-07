package io.bridger;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

/**
 * Core multipurpose command engine for Bridger.
 * Handles JSON-RPC and Broadcast Intent commands for any same-UID target process/package:
 * - ping / status
 * - pidof (native /proc scan + Java fallback)
 * - maps (untruncated /proc/<pid>/maps with perm/path/min_size filters)
 * - fs.ls / fs.stat / fs.copy / fs.feed / fs.pull / fs.mkdir / fs.rm / fs.read_text / fs.write_text
 * - mem.read / mem.write / mem.scan / mem.redirect
 * - intent.broadcast / intent.start
 * - exec (run native helper binaries or shell commands in the shared UID context)
 */
public final class BridgerEngine {
    public static final String TAG = "BridgerEngine";
    public static final String VERSION = "2.0.0";
    public static final int DEFAULT_RPC_PORT = 27044;
    public static final int DEFAULT_FRIDA_PORT = 27043;

    private static volatile String sLastCommandSummary = "Ready";
    private static volatile long sLastCommandTimeMs = 0L;
    private static volatile int sCommandCount = 0;

    private BridgerEngine() {}

    public static String getLastCommandSummary() {
        return sLastCommandSummary;
    }

    public static long getLastCommandTimeMs() {
        return sLastCommandTimeMs;
    }

    public static int getCommandCount() {
        return sCommandCount;
    }

    public static JSONObject execute(Context context, JSONObject req) {
        long t0 = System.currentTimeMillis();
        JSONObject resp = new JSONObject();
        String cmd = req != null ? req.optString("cmd", req.optString("op", "status")).trim() : "status";
        String reqId = req != null ? req.optString("id", "") : "";
        sCommandCount++;
        sLastCommandTimeMs = t0;
        try {
            if (!reqId.isEmpty()) {
                resp.put("id", reqId);
            }
            resp.put("cmd", cmd);
            BridgerNative.ensureLoaded();

            switch (cmd) {
                case "ping":
                case "status":
                    handleStatus(context, req, resp);
                    break;
                case "pidof":
                    handlePidOf(req, resp);
                    break;
                case "maps":
                    handleMaps(req, resp);
                    break;
                case "fs.ls":
                case "ls":
                    handleFsLs(req, resp);
                    break;
                case "fs.stat":
                case "stat":
                    handleFsStat(req, resp);
                    break;
                case "fs.copy":
                case "copy":
                    handleFsCopy(req, resp);
                    break;
                case "fs.feed":
                case "feed":
                    handleFsFeed(context, req, resp);
                    break;
                case "fs.pull":
                case "pull":
                    handleFsPull(req, resp);
                    break;
                case "fs.mkdir":
                case "mkdir":
                    handleFsMkdir(req, resp);
                    break;
                case "fs.rm":
                case "rm":
                    handleFsRm(req, resp);
                    break;
                case "fs.read_text":
                case "read_text":
                    handleFsReadText(req, resp);
                    break;
                case "fs.write_text":
                case "write_text":
                    handleFsWriteText(req, resp);
                    break;
                case "mem.read":
                    handleMemRead(req, resp);
                    break;
                case "mem.write":
                case "mem.poke":
                case "poke":
                    handleMemWrite(req, resp);
                    break;
                case "mem.scan":
                case "scan":
                    handleMemScan(req, resp);
                    break;
                case "mem.redirect":
                case "redirect":
                    handleMemRedirect(req, resp);
                    break;
                case "intent.broadcast":
                case "broadcast":
                    handleIntentBroadcast(context, req, resp);
                    break;
                case "intent.start":
                case "start_activity":
                    handleIntentStart(context, req, resp);
                    break;
                case "exec":
                    handleExec(context, req, resp);
                    break;
                default:
                    resp.put("ok", false);
                    resp.put("error", "unknown_cmd:" + cmd);
                    break;
            }
            if (!resp.has("ok")) {
                resp.put("ok", true);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Command failed: " + cmd, t);
            try {
                resp.put("ok", false);
                resp.put("error", t.getClass().getSimpleName() + ": " + t.getMessage());
            } catch (Exception ignored) {}
        }

        long elapsed = System.currentTimeMillis() - t0;
        try {
            resp.put("elapsed_ms", elapsed);
            resp.put("bridge_pid", Process.myPid());
            resp.put("bridge_uid", Process.myUid());
        } catch (Exception ignored) {}

        sLastCommandSummary = cmd + " -> " + (resp.optBoolean("ok") ? "OK" : resp.optString("error", "ERR"))
                + " (" + elapsed + "ms)";
        persistLastResult(context, resp);
        return resp;
    }

    private static void handleStatus(Context context, JSONObject req, JSONObject resp) throws Exception {
        resp.put("ok", true);
        resp.put("version", VERSION);
        resp.put("package", context != null ? context.getPackageName() : "io.bridger");
        resp.put("pid", Process.myPid());
        resp.put("uid", Process.myUid());
        resp.put("abi", Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "arm64-v8a");
        resp.put("sdk_int", Build.VERSION.SDK_INT);
        resp.put("native_loaded", BridgerNative.isNativeLoaded());
        resp.put("frida_loaded", BridgerNative.isFridaLoaded());
        resp.put("rpc_port", BridgerService.getActivePort());
        resp.put("frida_port", DEFAULT_FRIDA_PORT);
        resp.put("commands_executed", sCommandCount);

        String targetPkg = req != null ? req.optString("target_pkg", "") : "";
        if (!targetPkg.isEmpty()) {
            resp.put("target_pkg", targetPkg);
            resp.put("target_pid", resolvePid(req));
            File targetData = new File("/data/data/" + targetPkg);
            resp.put("target_data_exists", targetData.exists());
            resp.put("target_data_readable", targetData.canRead());
            resp.put("target_data_writable", targetData.canWrite());
        }
    }

    public static int resolvePid(JSONObject req) {
        if (req == null) return -1;
        int pid = req.optInt("pid", -1);
        if (pid > 0) return pid;
        String targetPkg = req.optString("target_pkg", req.optString("process", "")).trim();
        if (targetPkg.isEmpty()) return -1;
        if (BridgerNative.isNativeLoaded()) {
            int found = BridgerNative.findPidByName(targetPkg);
            if (found > 0) return found;
        }
        return findPidFallback(targetPkg);
    }

    public static int findPidFallback(String processName) {
        if (processName == null || processName.isEmpty()) return -1;
        File procDir = new File("/proc");
        File[] entries = procDir.listFiles();
        if (entries == null) return -1;
        int myPid = Process.myPid();
        for (File entry : entries) {
            String name = entry.getName();
            if (!isDigits(name)) continue;
            int pid = Integer.parseInt(name);
            if (pid == myPid) continue;
            File cmdlineFile = new File(entry, "cmdline");
            try (FileInputStream fis = new FileInputStream(cmdlineFile)) {
                byte[] buf = new byte[256];
                int n = fis.read(buf);
                if (n > 0) {
                    int len = 0;
                    while (len < n && buf[len] != 0) len++;
                    String cmd = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
                    if (processName.equals(cmd)) {
                        return pid;
                    }
                }
            } catch (Exception ignored) {}
        }
        return -1;
    }

    private static boolean isDigits(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static void handlePidOf(JSONObject req, JSONObject resp) throws Exception {
        String target = req.optString("target_pkg", req.optString("process", "")).trim();
        int pid = resolvePid(req);
        resp.put("target_pkg", target);
        resp.put("pid", pid);
        resp.put("ok", pid > 0);
        if (pid <= 0) {
            resp.put("error", "process_not_found:" + target);
        }
    }

    private static void handleMaps(JSONObject req, JSONObject resp) throws Exception {
        int pid = resolvePid(req);
        if (pid <= 0) {
            resp.put("ok", false);
            resp.put("error", "invalid_or_missing_pid");
            return;
        }
        String permFilter = req.optString("perm", "");
        String pathFilter = req.optString("path", "");
        long minSize = req.optLong("min_size", 0L);

        resp.put("pid", pid);
        if (BridgerNative.isNativeLoaded()) {
            String jsonStr = BridgerNative.readMapsJson(
                    pid,
                    permFilter.isEmpty() ? null : permFilter,
                    pathFilter.isEmpty() ? null : pathFilter,
                    minSize
            );
            JSONArray arr = new JSONArray(jsonStr != null ? jsonStr : "[]");
            resp.put("count", arr.length());
            resp.put("regions", arr);
            resp.put("ok", true);
            return;
        }

        // Java fallback if native lib isn't loaded
        JSONArray arr = new JSONArray();
        File mapsFile = new File("/proc/" + pid + "/maps");
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(mapsFile), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                int dash = line.indexOf('-');
                int sp1 = line.indexOf(' ', dash + 1);
                if (dash < 0 || sp1 < 0 || sp1 + 5 > line.length()) continue;
                long start = Long.parseUnsignedLong(line.substring(0, dash), 16);
                long end = Long.parseUnsignedLong(line.substring(dash + 1, sp1), 16);
                String perms = line.substring(sp1 + 1, sp1 + 5);
                long size = end - start;
                if (minSize > 0 && size < minSize) continue;
                if (!permFilter.isEmpty() && !perms.contains(permFilter)) continue;
                String path = "";
                int slash = line.indexOf('/', sp1 + 5);
                if (slash < 0) slash = line.indexOf('[', sp1 + 5);
                if (slash >= 0) path = line.substring(slash).trim();
                if (!pathFilter.isEmpty() && !path.contains(pathFilter)) continue;

                JSONObject reg = new JSONObject();
                reg.put("start", String.format("0x%x", start));
                reg.put("end", String.format("0x%x", end));
                reg.put("size", size);
                reg.put("perms", perms);
                reg.put("path", path);
                arr.put(reg);
            }
        }
        resp.put("count", arr.length());
        resp.put("regions", arr);
        resp.put("ok", true);
    }

    private static String resolveTargetPath(JSONObject req, String key, String defaultSubpath) {
        String explicit = req.optString(key, "").trim();
        if (!explicit.isEmpty()) return explicit;
        String targetPkg = req.optString("target_pkg", "").trim();
        String rel = req.optString("rel_path", defaultSubpath).trim();
        if (!targetPkg.isEmpty()) {
            if (rel.startsWith("/")) rel = rel.substring(1);
            return "/data/data/" + targetPkg + "/" + rel;
        }
        return "";
    }

    private static void handleFsLs(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "files");
        if (path.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_path_or_target_pkg");
            return;
        }
        File dir = new File(path);
        resp.put("path", dir.getAbsolutePath());
        if (!dir.exists()) {
            resp.put("ok", false);
            resp.put("error", "not_found");
            return;
        }
        JSONArray items = new JSONArray();
        if (dir.isDirectory()) {
            File[] children = dir.listFiles();
            if (children != null) {
                for (File f : children) {
                    JSONObject item = new JSONObject();
                    item.put("name", f.getName());
                    item.put("is_dir", f.isDirectory());
                    item.put("size", f.isFile() ? f.length() : 0L);
                    item.put("mtime", f.lastModified());
                    item.put("readable", f.canRead());
                    item.put("writable", f.canWrite());
                    items.put(item);
                }
            }
        } else {
            JSONObject item = new JSONObject();
            item.put("name", dir.getName());
            item.put("is_dir", false);
            item.put("size", dir.length());
            item.put("mtime", dir.lastModified());
            items.put(item);
        }
        resp.put("count", items.length());
        resp.put("entries", items);
        resp.put("ok", true);
    }

    private static void handleFsStat(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "files");
        File f = new File(path);
        resp.put("path", f.getAbsolutePath());
        resp.put("exists", f.exists());
        resp.put("is_dir", f.isDirectory());
        resp.put("is_file", f.isFile());
        resp.put("size", f.exists() ? f.length() : -1L);
        resp.put("mtime", f.exists() ? f.lastModified() : 0L);
        resp.put("readable", f.canRead());
        resp.put("writable", f.canWrite());
        resp.put("executable", f.canExecute());
        resp.put("ok", true);
    }

    public static long copyStream(File src, File dst) throws Exception {
        File parent = dst.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        long total = 0L;
        byte[] buf = new byte[65536];
        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dst)) {
            int n;
            while ((n = fis.read(buf)) > 0) {
                fos.write(buf, 0, n);
                total += n;
            }
            fos.getFD().sync();
        }
        return total;
    }

    private static void handleFsCopy(JSONObject req, JSONObject resp) throws Exception {
        String srcPath = req.optString("src", "").trim();
        String dstPath = resolveTargetPath(req, "dst", "files");
        if (srcPath.isEmpty() || dstPath.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_src_or_dst");
            return;
        }
        File src = new File(srcPath);
        File dst = new File(dstPath);
        if (dst.isDirectory()) {
            dst = new File(dst, src.getName());
        }
        long bytes = copyStream(src, dst);
        if (req.optBoolean("chmod_exec", false)) {
            dst.setExecutable(true, false);
            dst.setReadable(true, false);
        }
        resp.put("src", src.getAbsolutePath());
        resp.put("dst", dst.getAbsolutePath());
        resp.put("bytes", bytes);
        resp.put("ok", true);
    }

    private static void handleFsFeed(Context context, JSONObject req, JSONObject resp) throws Exception {
        String srcPath = req.optString("src", "").trim();
        String targetPkg = req.optString("target_pkg", "").trim();
        String inboxRel = req.optString("inbox_rel", "files/inbox").trim();
        String dstName = req.optString("name", "").trim();

        if (srcPath.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_src");
            return;
        }
        File src = new File(srcPath);
        if (dstName.isEmpty()) {
            dstName = src.getName();
        }
        String dstPath = req.optString("dst", "").trim();
        if (dstPath.isEmpty()) {
            if (targetPkg.isEmpty()) {
                resp.put("ok", false);
                resp.put("error", "missing_target_pkg_or_dst");
                return;
            }
            dstPath = "/data/data/" + targetPkg + "/" + inboxRel + "/" + dstName;
        }

        File dst = new File(dstPath);
        long bytes = copyStream(src, dst);
        resp.put("src", src.getAbsolutePath());
        resp.put("dst", dst.getAbsolutePath());
        resp.put("bytes", bytes);

        String notifyAction = req.optString("notify_action", "").trim();
        if (!notifyAction.isEmpty() && context != null) {
            Intent notify = new Intent(notifyAction);
            if (req.optBoolean("explicit_pkg", false) && !targetPkg.isEmpty()) {
                notify.setPackage(targetPkg);
            }
            notify.putExtra("file", dst.getName());
            notify.putExtra("path", dst.getAbsolutePath());
            context.sendBroadcast(notify);
            resp.put("notified_action", notifyAction);
        }
        resp.put("ok", true);
    }

    private static void handleFsPull(JSONObject req, JSONObject resp) throws Exception {
        String srcPath = resolveTargetPath(req, "src", "");
        String dstPath = req.optString("dst", "").trim();
        if (srcPath.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_src");
            return;
        }
        File src = new File(srcPath);
        if (!src.exists()) {
            resp.put("ok", false);
            resp.put("error", "not_found:" + srcPath);
            return;
        }
        if (!dstPath.isEmpty()) {
            File dst = new File(dstPath);
            if (dst.isDirectory()) {
                dst = new File(dst, src.getName());
            }
            long bytes = copyStream(src, dst);
            resp.put("src", src.getAbsolutePath());
            resp.put("dst", dst.getAbsolutePath());
            resp.put("bytes", bytes);
            resp.put("ok", true);
            return;
        }
        // Inline base64 pull for small files (<= 4MB)
        long len = src.length();
        if (len > 4 * 1024 * 1024) {
            resp.put("ok", false);
            resp.put("error", "file_too_large_for_inline_pull_specify_dst");
            return;
        }
        byte[] data = readAllBytes(src);
        resp.put("src", src.getAbsolutePath());
        resp.put("bytes", data.length);
        resp.put("data_b64", Base64.encodeToString(data, Base64.NO_WRAP));
        resp.put("ok", true);
    }

    private static void handleFsMkdir(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "files");
        File dir = new File(path);
        boolean created = dir.exists() || dir.mkdirs();
        resp.put("path", dir.getAbsolutePath());
        resp.put("ok", created && dir.isDirectory());
    }

    private static boolean deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) {
                    deleteRecursive(c);
                }
            }
        }
        return f.delete();
    }

    private static void handleFsRm(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "");
        if (path.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_path");
            return;
        }
        File f = new File(path);
        boolean recursive = req.optBoolean("recursive", false);
        boolean deleted = f.exists() && (recursive ? deleteRecursive(f) : f.delete());
        resp.put("path", f.getAbsolutePath());
        resp.put("deleted", deleted);
        resp.put("ok", deleted || !f.exists());
    }

    private static void handleFsReadText(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "");
        File f = new File(path);
        if (!f.exists()) {
            resp.put("ok", false);
            resp.put("error", "not_found:" + path);
            return;
        }
        byte[] data = readAllBytes(f);
        resp.put("path", f.getAbsolutePath());
        resp.put("bytes", data.length);
        resp.put("text", new String(data, StandardCharsets.UTF_8));
        resp.put("ok", true);
    }

    private static void handleFsWriteText(JSONObject req, JSONObject resp) throws Exception {
        String path = resolveTargetPath(req, "path", "");
        String text = req.optString("text", "");
        boolean append = req.optBoolean("append", false);
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream fos = new FileOutputStream(f, append)) {
            fos.write(bytes);
            fos.getFD().sync();
        }
        resp.put("path", f.getAbsolutePath());
        resp.put("bytes", bytes.length);
        resp.put("ok", true);
    }

    private static long parseAddress(Object addrObj) {
        if (addrObj instanceof Number) {
            return ((Number) addrObj).longValue();
        }
        String s = String.valueOf(addrObj).trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseUnsignedLong(s);
    }

    private static byte[] parsePatternBytes(JSONObject req) {
        if (req.has("data_b64")) {
            return Base64.decode(req.optString("data_b64", ""), Base64.DEFAULT);
        }
        if (req.has("hex")) {
            String hex = req.optString("hex", "").replaceAll("\\s+", "");
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }
        String text = req.optString("pattern", req.optString("text", ""));
        boolean utf16 = req.optBoolean("utf16", false);
        return text.getBytes(utf16 ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static void handleMemRead(JSONObject req, JSONObject resp) throws Exception {
        int pid = resolvePid(req);
        long address = parseAddress(req.get("address"));
        int length = req.optInt("length", 64);
        if (pid <= 0 || length <= 0) {
            resp.put("ok", false);
            resp.put("error", "invalid_pid_or_length");
            return;
        }
        byte[] data = BridgerNative.readProcessMemory(pid, address, length);
        if (data == null) {
            resp.put("ok", false);
            resp.put("error", "mem_read_failed");
            return;
        }
        resp.put("pid", pid);
        resp.put("address", String.format("0x%x", address));
        resp.put("bytes", data.length);
        resp.put("hex", bytesToHex(data));
        resp.put("data_b64", Base64.encodeToString(data, Base64.NO_WRAP));
        resp.put("ok", true);
    }

    private static void handleMemWrite(JSONObject req, JSONObject resp) throws Exception {
        int pid = resolvePid(req);
        long address = parseAddress(req.get("address"));
        byte[] data = parsePatternBytes(req);
        if (pid <= 0 || data == null || data.length == 0) {
            resp.put("ok", false);
            resp.put("error", "invalid_pid_or_data");
            return;
        }
        int written = BridgerNative.writeProcessMemory(pid, address, data);
        resp.put("pid", pid);
        resp.put("address", String.format("0x%x", address));
        resp.put("written", written);
        resp.put("ok", written == data.length);
        if (written < 0) {
            resp.put("error", "errno_" + (-written));
        }
    }

    private static void handleMemScan(JSONObject req, JSONObject resp) throws Exception {
        int pid = resolvePid(req);
        byte[] pattern = parsePatternBytes(req);
        if (pid <= 0 || pattern == null || pattern.length == 0) {
            resp.put("ok", false);
            resp.put("error", "invalid_pid_or_pattern");
            return;
        }
        String permFilter = req.optString("perm", "r");
        String pathFilter = req.optString("path", "");
        int maxHits = req.optInt("max_hits", 256);

        String jsonStr = BridgerNative.scanMemoryJson(
                pid,
                pattern,
                permFilter.isEmpty() ? null : permFilter,
                pathFilter.isEmpty() ? null : pathFilter,
                maxHits
        );
        JSONArray hits = new JSONArray(jsonStr != null ? jsonStr : "[]");
        resp.put("pid", pid);
        resp.put("count", hits.length());
        resp.put("hits", hits);
        resp.put("ok", true);
    }

    private static void handleMemRedirect(JSONObject req, JSONObject resp) throws Exception {
        int pid = resolvePid(req);
        if (pid <= 0) {
            resp.put("ok", false);
            resp.put("error", "invalid_or_missing_pid");
            return;
        }
        JSONArray results = new JSONArray();
        if (req.has("pairs")) {
            JSONArray pairs = req.getJSONArray("pairs");
            for (int i = 0; i < pairs.length(); i++) {
                JSONObject pair = pairs.getJSONObject(i);
                String from = pair.getString("from");
                String to = pair.getString("to");
                String resJson = BridgerNative.redirectStrings(pid, from, to);
                results.put(new JSONObject(resJson));
            }
        } else {
            String from = req.getString("from");
            String to = req.getString("to");
            String resJson = BridgerNative.redirectStrings(pid, from, to);
            results.put(new JSONObject(resJson));
        }
        resp.put("pid", pid);
        resp.put("redirects", results);
        resp.put("ok", true);
    }

    private static void applyExtras(Intent intent, JSONObject extras) throws Exception {
        if (extras == null) return;
        Iterator<String> keys = extras.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            Object v = extras.get(k);
            if (v instanceof Boolean) {
                intent.putExtra(k, (Boolean) v);
            } else if (v instanceof Integer) {
                intent.putExtra(k, (Integer) v);
            } else if (v instanceof Long) {
                intent.putExtra(k, (Long) v);
            } else if (v instanceof Double) {
                intent.putExtra(k, (Double) v);
            } else if (v != null) {
                intent.putExtra(k, String.valueOf(v));
            }
        }
    }

    private static void handleIntentBroadcast(Context context, JSONObject req, JSONObject resp) throws Exception {
        String action = req.getString("action");
        Intent intent = new Intent(action);
        String pkg = req.optString("target_pkg", req.optString("package", "")).trim();
        String component = req.optString("component", "").trim();
        if (!pkg.isEmpty() && !component.isEmpty()) {
            intent.setClassName(pkg, component);
        } else if (!pkg.isEmpty() && req.optBoolean("explicit_pkg", false)) {
            intent.setPackage(pkg);
        }
        applyExtras(intent, req.optJSONObject("extras"));
        context.sendBroadcast(intent);
        resp.put("action", action);
        resp.put("ok", true);
    }

    private static void handleIntentStart(Context context, JSONObject req, JSONObject resp) throws Exception {
        String pkg = req.optString("target_pkg", req.optString("package", "")).trim();
        String component = req.optString("component", "").trim();
        String action = req.optString("action", Intent.ACTION_MAIN).trim();
        Intent intent = new Intent(action);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (!pkg.isEmpty() && !component.isEmpty()) {
            intent.setClassName(pkg, component);
        } else if (!pkg.isEmpty()) {
            Intent launch = context.getPackageManager().getLaunchIntentForPackage(pkg);
            if (launch != null) {
                intent = launch;
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            } else {
                intent.setPackage(pkg);
            }
        }
        applyExtras(intent, req.optJSONObject("extras"));
        context.startActivity(intent);
        resp.put("started", true);
        resp.put("ok", true);
    }

    private static void handleExec(Context context, JSONObject req, JSONObject resp) throws Exception {
        String command = req.optString("command", "").trim();
        int timeoutSec = req.optInt("timeout_sec", 15);
        if (command.isEmpty()) {
            resp.put("ok", false);
            resp.put("error", "missing_command");
            return;
        }
        ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", command);
        String cwd = req.optString("cwd", "").trim();
        if (!cwd.isEmpty()) {
            pb.directory(new File(cwd));
        } else if (context != null) {
            pb.directory(context.getFilesDir());
        }
        java.lang.Process proc = pb.start();
        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        Thread tOut = pumpStream(proc.getInputStream(), outBuf);
        Thread tErr = pumpStream(proc.getErrorStream(), errBuf);

        boolean finished = proc.waitFor(timeoutSec, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
        }
        tOut.join(1000);
        tErr.join(1000);

        resp.put("command", command);
        resp.put("timed_out", !finished);
        resp.put("exit_code", finished ? proc.exitValue() : -1);
        resp.put("stdout", new String(outBuf.toByteArray(), StandardCharsets.UTF_8));
        resp.put("stderr", new String(errBuf.toByteArray(), StandardCharsets.UTF_8));
        resp.put("ok", finished && proc.exitValue() == 0);
    }

    private static Thread pumpStream(final InputStream is, final ByteArrayOutputStream os) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[4096];
            int n;
            try {
                while ((n = is.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
            } catch (Exception ignored) {}
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static byte[] readAllBytes(File f) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream((int) Math.min(f.length(), 65536));
        byte[] buf = new byte[16384];
        try (FileInputStream fis = new FileInputStream(f)) {
            int n;
            while ((n = fis.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
        }
        return bos.toByteArray();
    }

    public static void persistLastResult(Context context, JSONObject resp) {
        String body = resp.toString() + "\n";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (context != null) {
            try {
                File internal = new File(context.getFilesDir(), "bridger_last_result.json");
                try (FileOutputStream fos = new FileOutputStream(internal)) {
                    fos.write(bytes);
                }
            } catch (Exception ignored) {}
        }
        try {
            File pub = new File("/sdcard/Download/bridger_last_result.json");
            try (FileOutputStream fos = new FileOutputStream(pub)) {
                fos.write(bytes);
            }
        } catch (Exception ignored) {}
    }
}
