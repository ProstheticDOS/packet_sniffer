package com.example.packetsniffer;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
  private static final int VPN_REQUEST_CODE = 1;
  private TextView statusText;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    statusText = new TextView(this);
    statusText.setText("Welcome to packet_sniffer!\nInitializing...");
    statusText.setTextColor(Color.WHITE);
    statusText.setTextSize(18);
    statusText.setPadding(40, 100, 40, 40);
    statusText.setBackgroundColor(Color.BLACK);
    setContentView(statusText);

    Intent intent = VpnService.prepare(this);
    if (intent != null) {
      startActivityForResult(intent, VPN_REQUEST_CODE);
    } else {
      onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
      statusText.setText("packet_sniffer\nStarting service...");
      startService(new Intent(this, SnifferVpnService.class));
    } else {
      statusText.setText("packet_sniffer\nPermission denied.");
    }
  }
}
