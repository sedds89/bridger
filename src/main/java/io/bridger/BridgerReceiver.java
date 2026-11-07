package io.bridger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

/**
 * BroadcastReceiver for Bridger commands and file feeds.
 * Accepts:
 *  - Action `io.bridger.COMMAND`: executes any BridgerEngine command from `--es json '{...}'`
 *    or individual intent extras (`--es cmd ...`, `--es target_pkg ...`, `--es src ...`, etc.)
 *  - Action `io.bridger.FEED`: copies a staged file into a target package's inbox directory
 *    and optionally broadcasts a wake intent.
 */
public class BridgerReceiver extends BroadcastReceiver {
    public static final String TAG = "BridgerReceiver";
    public static final String ACTION_COMMAND = "io.bridger.COMMAND";
    public static final String ACTION_FEED = "io.bridger.FEED";
    public static final String ACTION_RESULT = "io.bridger.RESULT";

    @Override
    public void onReceive(final Context context, final Intent intent) {
        if (intent == null) return;
        BridgerNative.ensureLoaded();

        // Ensure the sticky service is running whenever a broadcast wakes Bridger
        try {
            Intent svc = new Intent(context, BridgerService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(svc);
            } else {
                context.startService(svc);
            }
        } catch (Throwable ignored) {}

        final PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                JSONObject req = buildRequestFromIntent(intent);
                JSONObject resp = BridgerEngine.execute(context, req);
                Log.i(TAG, "Result: " + resp.toString());
                try {
                    Intent out = new Intent(ACTION_RESULT);
                    out.putExtra("json", resp.toString());
                    out.putExtra("ok", resp.optBoolean("ok", false));
                    context.sendBroadcast(out);
                } catch (Throwable ignored) {}
            } catch (Throwable t) {
                Log.e(TAG, "Broadcast execution failed", t);
            } finally {
                pending.finish();
            }
        }, "BridgerBroadcastWorker").start();
    }

    public static JSONObject buildRequestFromIntent(Intent intent) throws Exception {
        String rawJson = intent.getStringExtra("json");
        JSONObject req = (rawJson != null && !rawJson.trim().isEmpty())
                ? new JSONObject(rawJson)
                : new JSONObject();

        String action = intent.getAction() != null ? intent.getAction() : "";
        if (!req.has("cmd") && !req.has("op")) {
            if (ACTION_FEED.equals(action)) {
                req.put("cmd", "fs.feed");
            } else {
                req.put("cmd", intent.getStringExtra("cmd") != null ? intent.getStringExtra("cmd") : "status");
            }
        }

        Bundle extras = intent.getExtras();
        if (extras != null) {
            for (String key : extras.keySet()) {
                if ("json".equals(key) || req.has(key)) continue;
                Object val = extras.get(key);
                if (val != null) {
                    req.put(key, val);
                }
            }
        }
        return req;
    }
}
