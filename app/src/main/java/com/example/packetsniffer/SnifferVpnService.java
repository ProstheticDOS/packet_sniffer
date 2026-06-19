package com.example.packetsniffer;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.lang.annotation.Native;

import android.content.Intent;
import android.os.IBinder;

public class SnifferVpnService extends VpnService {
  private ParcelFileDescriptor vpnInterface;
  private Thread workerThread;

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    Builder builder = new Builder();
    builder.setSession("packet_sniffer")
        .addAddress("10.0.0.2", 32) // Assign IP to VPN interface
        .addRoute("0.0.0.0", 0) // Route ALL traffic through VPN
        .addDnsServer("8.8.8.8") // Use Google DNS
        .setMtu(1500); // Standard Ethernet MTU

    vpnInterface = builder.establish();
    if (vpnInterface == null) {
      stopSelf();
      return START_NOT_STICKY;
    }

    int fd = vpnInterface.getFd();
    workerThread = new Thread(() -> NativeBridge.runPacketLoop(fd));
    workerThread.start();

    return START_STICKY;
  }

  @Override
  public void onDestroy() {

    NativeBridge.stopPacketLoop();

    // Close the Vpn interface
    if (vpnInterface != null) {
      try {
        vpnInterface.close();
      } catch (Exception ignored) {
      }
    }

    // Interrupt and wait for worker thread to finish
    if (workerThread != null && workerThread.isAlive()) {
      workerThread.interrupt();
      try {
        workerThread.join(3000); // 3 second timeout
      } catch (InterruptedException e) {
      } // handle exception to prevent the app from creating crash logs
    }

    super.onDestroy();
  }

  @Override
  public IBinder onBind(Intent intent) {
    return null;
  } // binding unsupported
}
