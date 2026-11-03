import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.UserHandle;
import android.util.Base64;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Properties;

/** Root installer helper for this manager's package state; never runs in apps. */
public final class HmaManagerMigration {
    private static final String PACKAGE = "org.frknkrc44.hma_oss";
    private static final String[] ALIASES = {
        ".MainActivityLauncher", ".MainActivityLauncherAlt", ".MainActivityLauncherAlt2",
        ".MainActivityLauncherAlt3", ".MainActivityLauncherAlt4"
    };

    private static PackageManager manager(int user) throws Exception {
        if (Looper.myLooper() == null) Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object thread = activityThread.getMethod("systemMain").invoke(null);
        Context system = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
        Context context = (Context) Context.class.getMethod("createContextAsUser", UserHandle.class, int.class)
            .invoke(system, UserHandle.getUserHandleForUid(user * 100000), 0);
        return context.getPackageManager();
    }

    private static Properties read(String path) throws Exception {
        Properties properties = new Properties();
        try (FileInputStream in = new FileInputStream(path)) { properties.load(in); }
        return properties;
    }

    private static String signature(PackageManager pm) throws Exception {
        PackageInfo info = pm.getPackageInfo(PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES);
        if (info.signingInfo == null || info.signingInfo.getApkContentsSigners().length != 1)
            throw new IllegalStateException("Expected one HMA manager signing certificate");
        return Base64.encodeToString(info.signingInfo.getApkContentsSigners()[0].toByteArray(), Base64.NO_WRAP);
    }

    public static void main(String[] args) {
        try {
            String command = args[0];
            int user = Integer.parseInt(args[1]);
            PackageManager pm = manager(user);
            if (command.equals("uid")) {
                System.out.println(pm.getApplicationInfo(PACKAGE, 0).uid);
                return;
            }
            if (command.equals("capture")) {
                Properties properties = new Properties();
                properties.setProperty("package", PACKAGE);
                properties.setProperty("user", Integer.toString(user));
                properties.setProperty("uid", Integer.toString(pm.getApplicationInfo(PACKAGE, 0).uid));
                properties.setProperty("signature", signature(pm));
                properties.setProperty("enabled", Integer.toString(pm.getApplicationEnabledSetting(PACKAGE)));
                for (int i = 0; i < ALIASES.length; i++) {
                    int value = pm.getComponentEnabledSetting(new ComponentName(PACKAGE, PACKAGE + ALIASES[i]));
                    properties.setProperty("component." + i, Integer.toString(value));
                }
                try (FileOutputStream out = new FileOutputStream(args[2])) {
                    properties.store(out, "HMA manager package state before signature migration");
                }
                return;
            }
            Properties properties = read(args[2]);
            if (!PACKAGE.equals(properties.getProperty("package")) ||
                user != Integer.parseInt(properties.getProperty("user")))
                throw new IllegalArgumentException("Snapshot package/user mismatch");
            if (command.equals("restore")) {
                for (int i = 0; i < ALIASES.length; i++) {
                    pm.setComponentEnabledSetting(new ComponentName(PACKAGE, PACKAGE + ALIASES[i]),
                        Integer.parseInt(properties.getProperty("component." + i)), PackageManager.DONT_KILL_APP);
                }
                pm.setApplicationEnabledSetting(PACKAGE, Integer.parseInt(properties.getProperty("enabled")),
                    PackageManager.DONT_KILL_APP);
                return;
            }
            if (!command.equals("verify")) throw new IllegalArgumentException("Unknown command");
            if (pm.getApplicationEnabledSetting(PACKAGE) != Integer.parseInt(properties.getProperty("enabled")))
                throw new IllegalStateException("Application enabled state differs");
            for (int i = 0; i < ALIASES.length; i++) {
                if (pm.getComponentEnabledSetting(new ComponentName(PACKAGE, PACKAGE + ALIASES[i])) !=
                    Integer.parseInt(properties.getProperty("component." + i)))
                    throw new IllegalStateException("Launcher state differs: " + ALIASES[i]);
            }
            String expected = args[3].equals("original") ? properties.getProperty("signature") :
                Base64.encodeToString(Files.readAllBytes(Paths.get(args[3])), Base64.NO_WRAP);
            if (!signature(pm).equals(expected)) throw new IllegalStateException("Installed certificate differs");
            System.out.println("VERIFIED user=" + user);
        } catch (Throwable error) {
            error.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
