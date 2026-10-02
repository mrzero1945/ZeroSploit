package com.zerosploit.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Unpacks the privileged helper executable into the app's private files
 * directory.
 *
 * <p>The helper is a real {@code add_executable()} target, and that creates two
 * problems that make {@code jniLibs} unusable:
 *
 * <ul>
 *   <li>AGP only packages {@code add_library()} outputs, so {@code zsraw} never
 *       made it into the APK.
 *   <li>With {@code extractNativeLibs=false} there is no {@code lib/} directory
 *       on disk at all, so even if it were packaged there would be nothing to
 *       {@code exec}.
 * </ul>
 *
 * <p>So the binary travels as an asset under {@code zsraw/<abi>/zsraw} and is
 * copied out here on first launch. The copy is stamped with the APK's install
 * time, which means an app update re-extracts a fresh helper.
 */
public final class Helper {

    private static final String TAG = "ZeroSploit";

    private static String installedPath;

    private Helper() {}

    /**
     * Copies the helper for this device's ABI into {@code filesDir} and returns
     * its absolute path.
     *
     * @throws IOException if the asset is missing or cannot be written; the
     *     caller should surface this as "root features unavailable" rather than
     *     crashing, since only the raw/802.11 modules need the helper.
     */
    public static synchronized String install(Context ctx) throws IOException {
        if (installedPath != null) return installedPath;

        String abi = pickAbi(ctx);
        File out = new File(ctx.getFilesDir(), "zsraw-" + abi);

        if (!isCurrent(out, ctx)) {
            File tmp = new File(ctx.getFilesDir(), "zsraw-" + abi + ".part");
            try (InputStream in = ctx.getAssets().open("zsraw/" + abi + "/zsraw");
                 OutputStream os = new FileOutputStream(tmp)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
                os.flush();
                // fsync through the fd so a kill right after this cannot leave
                // us with a truncated executable that passes a size check.
                ((FileOutputStream) os).getFD().sync();
            }
            if (out.exists() && !out.delete()) {
                throw new IOException("cannot replace " + out);
            }
            if (!tmp.renameTo(out)) {
                throw new IOException("cannot move helper into place");
            }
            // Owner-only is enough: only root (via su) ever executes it, and
            // the file lives in our own sandbox.
            if (!out.setExecutable(true, true) || !out.setReadable(true, true)) {
                throw new IOException("chmod failed for " + out);
            }
        }

        if (!out.canExecute()) throw new IOException(out + " is not executable");
        installedPath = out.getAbsolutePath();
        Log.i(TAG, "privileged helper staged at " + installedPath);
        return installedPath;
    }

    /** Forgets the cached path; used after a failed install to allow a retry. */
    public static synchronized void reset() {
        installedPath = null;
    }

    // ------------------------------------------------------------------ internals

    /** First ABI this device supports that we actually shipped a build for. */
    private static String pickAbi(Context ctx) throws IOException {
        // Build.SUPPORTED_ABIS is the public API here; ApplicationInfo.supportedAbis
        // is a hidden field and is not part of the SDK.
        String[] supported = Build.SUPPORTED_ABIS;
        if (supported == null || supported.length == 0) {
            throw new IOException("device reports no supported ABIs");
        }
        for (String abi : supported) {
            try (InputStream in = ctx.getAssets().open("zsraw/" + abi + "/zsraw")) {
                if (in.read() >= 0) return abi;
            } catch (IOException ignored) {
                // not packaged for this ABI, try the next one
            }
        }
        throw new IOException(
                "no helper for ABIs " + Arrays.toString(supported) + " (reinstall the APK)");
    }

    /** True when the staged copy is still newer than the installed APK. */
    private static boolean isCurrent(File out, Context ctx) {
        if (!out.isFile() || out.length() == 0) return false;
        long installedAt;
        try {
            PackageInfo pi = ctx.getPackageManager()
                    .getPackageInfo(ctx.getPackageName(), 0);
            installedAt = pi.lastUpdateTime;
        } catch (Exception e) {
            // If we cannot tell, trust the file that is already there.
            return true;
        }
        return out.lastModified() >= installedAt;
    }
}
