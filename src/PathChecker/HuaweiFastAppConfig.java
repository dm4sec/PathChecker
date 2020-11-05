package PathChecker;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;


public class HuaweiFastAppConfig {
    private static final ArrayList<String> processDir = new ArrayList<String>();
    private static HashMap<String, String> entries = new HashMap<String, String> ();
    private static ArrayList<String> sanitizer = new ArrayList<String> ();
    private static ArrayList<String> target = new ArrayList<String> ();
    private static ArrayList<String> blacklist = new ArrayList<>();

    // put the collected information here
    static {
        // processDir.add("./testcase/fy_lucky.jar");
        processDir.add("./testcase/com.huawei.fastapp.dev.apk");

        entries.put("com.huawei.fastapp.app.management.ui.FastAppCenterActivity",
                "void onCreate(android.os.Bundle)");

        sanitizer.add("ix");
        sanitizer.add("void a(android.app.Activity,int)");

        target.add("com.huawei.fastapp.app.management.ui.FastAppCenterActivity");
        target.add("void initView()");

        blacklist.add("<androidx.");
    }

    public static ArrayList<String> getEntities()
    {
        return processDir;
    }

    public static HashMap<String, String> getEntries()
    {
        return entries;
    }

    public static ArrayList<String> getTarget()
    {
        return target;
    }

    public static ArrayList<String> getSanitizer() { return sanitizer; }

    public static ArrayList<String> getBlacklist() { return blacklist; }
}