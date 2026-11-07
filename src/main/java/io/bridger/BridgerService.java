package io.bridger;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Persistent Bridger Service.
 * Fixes the old BridgeActivity.finish() LMK termination bug by keeping a sticky
 * service alive with a local TCP JSON-RPC server on 127.0.0.1:27044 (configurable)
 * alongside optional Frida Gadget on 127.0.0.1:27043.
 */
public class BridgerService extends Service {
    public static final String TAG = "BridgerService";
    private static final String CHANNEL_ID = "bridger_channel";
    private static final int NOTIF_ID = 27044;

    private static volatile boolean sRunning = false;
    private static volatile int sActivePort = BridgerEngine.DEFAULT_RPC_PORT;
    private ServerSocket mServerSocket;
    private Thread mAcceptThread;

    public static boolean isRunning() {
        return sRunning;
    }

    public static int getActivePort() {
        return sActivePort;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        BridgerNative.ensureLoaded();
        sRunning = true;
        startForegroundSafely();
        startRpcServer(sActivePort);
        Log.i(TAG, "BridgerService created (PID=" + Process.myPid() + ", UID=" + Process.myUid() + ")");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        BridgerNative.ensureLoaded();
        if (intent != null) {
            int port = intent.getIntExtra("port", sActivePort);
            if (port > 0 && port != sActivePort) {
                stopRpcServer();
                sActivePort = port;
            }
            if (intent.hasExtra("json")) {
                final String rawJson = intent.getStringExtra("json");
                new Thread(() -> {
                    try {
                        JSONObject req = new JSONObject(rawJson != null ? rawJson : "{}");
                        BridgerEngine.execute(getApplicationContext(), req);
                    } catch (Exception e) {
                        Log.e(TAG, "Service intent command error", e);
                    }
                }).start();
            }
        }
        startRpcServer(sActivePort);
        return START_STICKY;
    }

    private void startForegroundSafely() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel ch = new NotificationChannel(
                        CHANNEL_ID,
                        "Bridger RPC Service",
                        NotificationManager.IMPORTANCE_LOW
                );
                ch.setDescription("Keeps Bridger cross-process RPC and Frida Gadget alive");
                nm.createNotificationChannel(ch);
            }
            Notification.Builder nb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? new Notification.Builder(this, CHANNEL_ID)
                    : new Notification.Builder(this);
            nb.setContentTitle("Bridger Active (UID " + Process.myUid() + ")")
                    .setContentText("RPC 127.0.0.1:" + sActivePort + (BridgerNative.isFridaLoaded() ? " | Frida :27043" : ""))
                    .setSmallIcon(android.R.drawable.stat_notify_sync)
                    .setOngoing(true);
            startForeground(NOTIF_ID, nb.build());
        } catch (Throwable t) {
            Log.w(TAG, "Foreground notification skipped: " + t.getMessage());
        }
    }

    private synchronized void startRpcServer(final int port) {
        if (mServerSocket != null && !mServerSocket.isClosed()) {
            return;
        }
        mAcceptThread = new Thread(() -> {
            try {
                mServerSocket = new ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"));
                sActivePort = port;
                Log.i(TAG, "Bridger TCP JSON-RPC listening on 127.0.0.1:" + port);
                while (!Thread.currentThread().isInterrupted() && !mServerSocket.isClosed()) {
                    final Socket client = mServerSocket.accept();
                    handleClientAsync(client);
                }
            } catch (Throwable t) {
                if (sRunning) {
                    Log.w(TAG, "RPC accept loop exited: " + t.getMessage());
                }
            }
        }, "BridgerRpcAccept");
        mAcceptThread.setDaemon(true);
        mAcceptThread.start();
    }

    private void handleClientAsync(final Socket client) {
        Thread worker = new Thread(() -> {
            try (Socket s = client;
                 BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                 BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8))) {
                s.setSoTimeout(30000);
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    JSONObject req;
                    try {
                        req = new JSONObject(line);
                    } catch (Exception parseErr) {
                        JSONObject err = new JSONObject();
                        err.put("ok", false);
                        err.put("error", "invalid_json:" + parseErr.getMessage());
                        writer.write(err.toString());
                        writer.write("\n");
                        writer.flush();
                        continue;
                    }
                    JSONObject resp = BridgerEngine.execute(getApplicationContext(), req);
                    writer.write(resp.toString());
                    writer.write("\n");
                    writer.flush();
                }
            } catch (Throwable t) {
                Log.d(TAG, "RPC client closed: " + t.getMessage());
            }
        }, "BridgerRpcWorker");
        worker.setDaemon(true);
        worker.start();
    }

    private synchronized void stopRpcServer() {
        try {
            if (mServerSocket != null) {
                mServerSocket.close();
            }
        } catch (Exception ignored) {}
        mServerSocket = null;
    }

    @Override
    public void onDestroy() {
        sRunning = false;
        stopRpcServer();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
