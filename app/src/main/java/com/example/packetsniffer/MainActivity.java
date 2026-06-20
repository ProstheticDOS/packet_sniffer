package com.example.packetsniffer;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.ScrollView;
import android.widget.TextView;
import android.text.util.Linkify;

public class MainActivity extends Activity {
  private static final int VPN_REQUEST_CODE = 1;
  private static MainActivity instance;

  private TextView statusText;
  private ScrollView scrollView; // Required for scrolling

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    instance = this;

    // Create a ScrollView to handle scrolling
    scrollView = new ScrollView(this);

    // Create the TextView
    statusText = new TextView(this);
    statusText.setText("Welcome to packet_sniffer!\nInitializing...");
    statusText.setTextColor(Color.WHITE);
    statusText.setTextSize(18);
    statusText.setPadding(40, 100, 40, 40);
    statusText.setBackgroundColor(Color.BLACK);
    statusText.setGravity(Gravity.START);
    statusText.setHorizontallyScrolling(false); // Ensure text wraps instead of scrolling horizontally
    statusText.setAutoLinkMask(Linkify.WEB_URLS);

    // Add TextView inside ScrollView
    scrollView.addView(statusText);

    // Set the ScrollView as the root content view
    setContentView(scrollView);

    // Request VPN permission
    Intent intent = VpnService.prepare(this);
    if (intent != null) {
      startActivityForResult(intent, VPN_REQUEST_CODE);
    } else {
      onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
    }
  }

  // Called by Rust to append logs.
  public static void printOnScreen(String data) {
    if (instance == null)
      return;

    instance.runOnUiThread(() -> {
      instance.statusText.append(data + "\n");

      // Scroll to bottom after appending
      // post() to ensure the layout has updated before scrolling
      instance.scrollView.post(() -> {
        int scrollY = instance.statusText.getLayout().getLineTop(instance.statusText.getLineCount())
            - instance.scrollView.getHeight();
        if (scrollY > 0) {
          instance.scrollView.scrollTo(0, scrollY);
        }
      });
    });
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
      // Append startup message
      statusText.append("\npacket_sniffer\nStarting service...\n");
      startService(new Intent(this, SnifferVpnService.class));
    } else {
      // Replace on failure to show clear error state
      statusText.append("packet_sniffer\nPermission denied.");
    }
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    instance = null; // clean our stuff— santising if you will, to prevent memory leaks
  }
}
