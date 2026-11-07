package io.bridger;

import android.util.Log;

/**
 * JNI wrapper for libbridger.so (src/native/bridger_jni.c) and optional libfrida-gadget.so.
 * Provides fast, untruncated cross-process /proc/<pid>/maps and /proc/<pid>/mem access
 * with automatic PTRACE_SEIZE + PTRACE_INTERRUPT fallback on restrictive Android kernels.
 */
public final class BridgerNative {
    private static final String TAG = "BridgerNative";
    private static boolean sNativeLoaded = false;
    private static boolean sFridaLoaded = false;
    private static String sNativeError = "";
    private static String sFridaError = "";

    static {
        ensureLoaded();
    }

    private BridgerNative() {}

    public static synchronized void ensureLoaded() {
        if (!sNativeLoaded) {
            try {
                System.loadLibrary("bridger");
                sNativeLoaded = true;
                sNativeError = "";
                Log.i(TAG, "libbridger.so loaded");
            } catch (Throwable t) {
                sNativeError = t.toString();
                Log.w(TAG, "libbridger.so not loaded: " + sNativeError);
            }
        }
        if (!sFridaLoaded) {
            try {
                System.loadLibrary("frida-gadget");
                sFridaLoaded = true;
                sFridaError = "";
                Log.i(TAG, "libfrida-gadget.so loaded");
            } catch (Throwable t) {
                sFridaError = t.toString();
            }
        }
    }

    public static boolean isNativeLoaded() {
        ensureLoaded();
        return sNativeLoaded;
    }

    public static boolean isFridaLoaded() {
        ensureLoaded();
        return sFridaLoaded;
    }

    public static String getNativeError() {
        return sNativeError;
    }

    public static String getFridaError() {
        return sFridaError;
    }

    public static native int findPidByName(String processName);
    public static native String readMapsJson(int pid, String permFilter, String pathFilter, long minSize);
    public static native byte[] readProcessMemory(int pid, long address, int length);
    public static native int writeProcessMemory(int pid, long address, byte[] data);
    public static native String scanMemoryJson(int pid, byte[] pattern, String permFilter, String pathFilter, int maxHits);
    public static native String redirectStrings(int pid, String oldStr, String newStr);
}
