package com.example.packetsniffer;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
  private static final int VPN_REQUEST_CODE = 1;
  private static final int FILE_PICK_REQUEST_CODE = 2;

  // Name the copied file is always stored under in app-internal storage.
  // Native code reads from this fixed path regardless of what the user
  // originally named their file.
  private static final String LIST_FILE_NAME = "list.txt";

  private static MainActivity instance;

  private TextView statusText;
  private ScrollView scrollView;
  private Button uploadButton;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    instance = this;

    setContentView(R.layout.activity_main);

    statusText = findViewById(R.id.status_text);
    scrollView = findViewById(R.id.log_scrollview);
    uploadButton = findViewById(R.id.upload_button);

    uploadButton.setOnClickListener(v -> openFilePicker());

    // Request VPN permission
    Intent intent = VpnService.prepare(this);
    if (intent != null) {
      startActivityForResult(intent, VPN_REQUEST_CODE);
    } else {
      onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
    }
  }

  private void openFilePicker() {
    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
    intent.addCategory(Intent.CATEGORY_OPENABLE);
    intent.setType("text/plain");
    // Some file managers tag .txt files with a generic mime type, so also
    // accept "*/*" pickers gracefully if text/plain returns nothing useful.
    try {
      startActivityForResult(intent, FILE_PICK_REQUEST_CODE);
    } catch (Exception e) {
      Toast.makeText(this, "No file picker app available", Toast.LENGTH_SHORT).show();
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
    super.onActivityResult(requestCode, resultCode, data);

    if (requestCode == VPN_REQUEST_CODE) {
      if (resultCode == RESULT_OK) {
        statusText.append("\npacket_sniffer\nStarting service...\n");
        startService(new Intent(this, SnifferVpnService.class));
      } else {
        statusText.append("packet_sniffer\nPermission denied.");
      }
      return;
    }

    if (requestCode == FILE_PICK_REQUEST_CODE) {
      if (resultCode == RESULT_OK && data != null && data.getData() != null) {
        handlePickedFile(data.getData());
      } else {
        statusText.append("\nFile selection cancelled.\n");
      }
    }
  }

  /**
   * Copies the picked file into app-internal storage as "list.txt" so
   * native (Rust/JNI) code can open it by a stable filesystem path.
   * content:// Uris from the system picker aren't resolvable from native
   * code, so this copy step is necessary rather than just passing the Uri.
   */
  private void handlePickedFile(Uri sourceUri) {
    String displayName = queryDisplayName(sourceUri);
    File destFile = new File(getFilesDir(), LIST_FILE_NAME);

    try (InputStream in = getContentResolver().openInputStream(sourceUri);
        OutputStream out = new FileOutputStream(destFile)) {

      if (in == null) {
        throw new java.io.IOException("Unable to open input stream for selected file");
      }

      byte[] buffer = new byte[8192];
      int bytesRead;
      long totalBytes = 0;
      while ((bytesRead = in.read(buffer)) != -1) {
        out.write(buffer, 0, bytesRead);
        totalBytes += bytesRead;
      }

      statusText.append("\nUploaded: " + displayName
          + "\nSaved to: " + destFile.getAbsolutePath()
          + " (" + totalBytes + " bytes)\n");

      onListFileReady(destFile);

    } catch (Exception e) {
      statusText.append("\nFailed to copy file: " + e.getMessage() + "\n");
    }
  }

  /**
   * Hook called once list.txt has been copied into internal storage and is
   * ready for native code to consume. Wire this up to your JNI call, e.g.:
   *
   * nativeLoadList(file.getAbsolutePath());
   *
   * where nativeLoadList is a `native` method backed by your Rust library.
   */
  private void onListFileReady(File file) {
    // TODO: call into native/Rust code with file.getAbsolutePath()
    // Example:
    // nativeLoadList(file.getAbsolutePath());
  }

  private String queryDisplayName(Uri uri) {
    String name = "list.txt";
    try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
      if (cursor != null && cursor.moveToFirst()) {
        int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
        if (nameIndex != -1) {
          name = cursor.getString(nameIndex);
        }
      }
    } catch (Exception ignored) {
      // Fall back to default name above.
    }
    return name;
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    instance = null; // clean our stuff— santising if you will, to prevent memory leaks
  }
}
