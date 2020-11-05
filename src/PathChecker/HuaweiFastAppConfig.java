package PathChecker;

import java.util.ArrayList;
import java.util.HashMap;


public class HuaweiFastAppConfig {
    private static final ArrayList<String> processDir = new ArrayList<String>();
    private static HashMap<String, String> entries = new HashMap<String, String> ();
    private static ArrayList<String> target = new ArrayList<String> ();
    private static ArrayList<String> sanitizer = new ArrayList<String> ();
    private static ArrayList<String> blacklist = new ArrayList<>();

    // put the collected information here
    static {
        // processDir.add("./testcase/fy_lucky.jar");
        processDir.add("./testcase/com.huawei.fastapp.dev.apk");

        entries.put("com.huawei.fastapp.api.module.image.ImageModule",
                "void getExifAttributes(com.alibaba.fastjson.JSONObject,com.taobao.weex.bridge.JSCallback)");

        sanitizer.add("lr");
        sanitizer.add("java.lang.String a(com.taobao.weex.WXSDKInstance,java.lang.String)");

        target.add("com.huawei.fastapp.api.module.image.ImageModule");
        target.add("void getExifFromAttributes(androidx.exifinterface.media.ExifInterface,java.util.HashMap[],com.alibaba.fastjson.JSONObject)");

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