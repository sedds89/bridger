package io.bridger;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Bridger status dashboard Activity.
 * Starts BridgerService on launch so the bridge stays alive in the background.
 * Supports `--ez headless true` to immediately finish() after starting BridgerService.
 */
public class BridgerActivity extends Activity {
    private TextView mStatusView;
    private Handler mHandler;
    private final Runnable mRefreshTask = new Runnable() {
        @Override
        public void run() {
            updateStatusText();
            if (mHandler != null) {
                mHandler.postDelayed(this, 1500);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        BridgerNative.ensureLoaded();

        Intent svc = new Intent(this, BridgerService.class);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(svc);
            } else {
                startService(svc);
            }
        } catch (Throwable t) {
            try {
                startService(svc);
            } catch (Throwable ignored) {}
        }

        Intent launchIntent = getIntent();
        if (launchIntent != null && launchIntent.getBooleanExtra("headless", false)) {
            finish();
            return;
        }

        buildDashboardUi();
        mHandler = new Handler(Looper.getMainLooper());
        updateStatusText();
    }

    private void buildDashboardUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#0F172A"));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (18 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Bridger v" + BridgerEngine.VERSION);
        title.setTextColor(Color.parseColor("#38BDF8"));
        title.setTextSize(22f);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Generic Cross-Process Same-UID Android Bridge");
        subtitle.setTextColor(Color.parseColor("#94A3B8"));
        subtitle.setTextSize(13f);
        subtitle.setPadding(0, 4, 0, 20);
        root.addView(subtitle);

        mStatusView = new TextView(this);
        mStatusView.setTextColor(Color.parseColor("#E2E8F0"));
        mStatusView.setBackgroundColor(Color.parseColor("#1E293B"));
        mStatusView.setTypeface(Typeface.MONOSPACE);
        mStatusView.setTextSize(13f);
        mStatusView.setPadding(pad, pad, pad, pad);
        root.addView(mStatusView);

        Button minimizeBtn = new Button(this);
        minimizeBtn.setText("Keep Running in Background");
        minimizeBtn.setOnClickListener(v -> moveTaskToBack(true));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        lp.topMargin = 24;
        root.addView(minimizeBtn, lp);

        scroll.addView(root);
        setContentView(scroll);
    }

    private void updateStatusText() {
        if (mStatusView == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append("Package      : ").append(getPackageName()).append("\n");
        sb.append("Process PID  : ").append(Process.myPid()).append("\n");
        sb.append("Shared UID   : ").append(Process.myUid()).append("\n");
        sb.append("Service      : ").append(BridgerService.isRunning() ? "RUNNING" : "STARTING").append("\n");
        sb.append("TCP JSON-RPC : 127.0.0.1:").append(BridgerService.getActivePort()).append("\n");
        sb.append("libbridger   : ").append(BridgerNative.isNativeLoaded() ? "LOADED" : "FALLBACK (" + BridgerNative.getNativeError() + ")").append("\n");
        sb.append("Frida Gadget : ").append(BridgerNative.isFridaLoaded() ? "LOADED (:27043)" : "NOT BUNDLED").append("\n");
        sb.append("Commands Run : ").append(BridgerEngine.getCommandCount()).append("\n");
        sb.append("Last Command : ").append(BridgerEngine.getLastCommandSummary()).append("\n\n");
        sb.append("ADB Forward Usage:\n");
        sb.append("  adb forward tcp:27044 tcp:27044\n");
        sb.append("  python client/bridger_cli.py status\n\n");
        sb.append("Broadcast Usage:\n");
        sb.append("  adb shell am broadcast -n ").append(getPackageName()).append("/io.bridger.BridgerReceiver \\\n");
        sb.append("    -a io.bridger.COMMAND --es cmd status");
        mStatusView.setText(sb.toString());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mHandler != null) {
            mHandler.removeCallbacks(mRefreshTask);
            mHandler.post(mRefreshTask);
        }
    }

    @Override
    protected void onPause() {
        if (mHandler != null) {
            mHandler.removeCallbacks(mRefreshTask);
        }
        super.onPause();
    }
}
