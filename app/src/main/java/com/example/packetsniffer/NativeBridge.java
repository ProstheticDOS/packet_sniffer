package com.example.packetsniffer;

public class NativeBridge {
  static {
    System.loadLibrary("packet_sniffer");
  }

  public static native void runPacketLoop(int fd); // passes the file descriptor over to the rust side

  public static native void stopPacketLoop(); // for stopping, duh
}
