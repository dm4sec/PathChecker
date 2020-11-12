package PathChecker;

import soot.*;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;

import java.util.*;
import java.util.logging.Logger;

public class CGAnalyzer extends SceneTransformer{

    private static Logger logInfo = Logger.getLogger("CGChecker");

    @Override
    protected void internalTransform(String s, Map<String, String> map) {


        logInfo.info("Start getting the entry.");
        Stats.setAnalysisStart();
        CGHelper cgHelper = new CGHelper();

        // preserve entries to pathSanitizer
        Set<SootMethod> entries_path = new HashSet<>();
        {
            SootMethod pathSanitizer = cgHelper.findMethod(
                    "lr",
                    "java.lang.String c(com.huawei.fastapp.core.FastSDKInstance,java.lang.String)"
            );

            if (pathSanitizer == null) {
                logInfo.warning("Can't find the sanitizer.");
                return;
            }

            this.callstack.clear();
            this.callstack.push(pathSanitizer);
            this.backwardTrackEntries(cgHelper, entries_path, pathSanitizer, 0);
        }

        // preserve js entries to pathSanitizer
        Set<SootMethod> js_entries_path = new HashSet<>();
        {
            for(SootMethod m: entries_path)
            {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            js_entries_path.add(m);
                            break;
                        }
                    }
                }
            }
        }

        // public static boolean a(java.lang.String r15, java.lang.String r16, long r17, int r19, boolean r20) throws com.huawei.secure.android.common.util.SecurityCommonException {
        // com.huawei.secure.android.common.util.k

        // preserve entries to unzipSanitizer
        // not tested
        Set<SootMethod> entries_path_1 = new HashSet<>();
        {
            SootMethod pathSanitizer_1 = cgHelper.findMethod(
                    "com.huawei.secure.android.common.util.k",
                    "boolean a(java.lang.String,java.lang.String,long,int,boolean)"
            );

            if (pathSanitizer_1 == null) {
                logInfo.warning("Can't find the sanitizer.");
                return;
            }

            this.callstack.clear();
            this.callstack.push(pathSanitizer_1);
            this.backwardTrackEntries(cgHelper, entries_path_1, pathSanitizer_1, 0);
        }

        // preserve js entries to unzipSanitizer
        Set<SootMethod> js_entries_path_1 = new HashSet<>();
        {
            for(SootMethod m: entries_path_1)
            {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            js_entries_path_1.add(m);
                            break;
                        }
                    }
                }
            }
        }

        {
            System.out.println("Total " + js_entries_path_1.size() + " entries protected by zip sanitizer");
            for(SootMethod m: js_entries_path_1){
                System.out.println(m.toString());
            }
        }

        // preserve entries to permSanitizer
        Set<SootMethod> entries_perm_0 = new HashSet<>();
        {
            SootMethod permSanitizer_0 = cgHelper.findMethod(
                    "com.huawei.fastapp.api.permission.DynamicPermission",
                    "boolean a(java.lang.String,java.lang.String)"
            );

            if (permSanitizer_0 == null) {
                logInfo.warning("Can't find the sanitizer.");
                return;
            }

            this.callstack.clear();
            this.callstack.push(permSanitizer_0);
            this.backwardTrackEntries(cgHelper, entries_perm_0, permSanitizer_0, 0);
        }

        // preserve js entries to permSanitizer
        Set<SootMethod> js_entries_perm_0 = new HashSet<>();
        {
            for(SootMethod m: entries_perm_0)
            {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            js_entries_perm_0.add(m);
                            break;
                        }
                    }
                }
            }
        }

        // .method private a(Landroid/content/Context;Lcom/taobao/weex/WXSDKInstance;Lcom/huawei/fastapp/api/permission/a;Ljava/lang/String;Z)V

        // preserve entries to permSanitizer_1
        Set<SootMethod> entries_perm_1 = new HashSet<>();
        {
            SootMethod permSanitizer_1 = cgHelper.findMethod(
                    "com.huawei.fastapp.api.permission.DynamicPermission",
                    "void a(android.content.Context,com.taobao.weex.WXSDKInstance,com.huawei.fastapp.api.permission.a,java.lang.String,boolean)"
            );

            if (permSanitizer_1 == null) {
                logInfo.warning("Can't find the sanitizer.");
                return;
            }

            this.callstack.clear();
            this.callstack.push(permSanitizer_1);
            this.backwardTrackEntries(cgHelper, entries_perm_1, permSanitizer_1, 0);
        }

        // preserve js entries to permSanitizer_1
        Set<SootMethod> js_entries_perm_1 = new HashSet<>();
        {
            for(SootMethod m: entries_perm_1)
            {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            js_entries_perm_1.add(m);
                            break;
                        }
                    }
                }
            }
        }

        Set<SootMethod> js_entries = new HashSet<>();         // collect all jsmethod
        {
            for(SootClass c: Scene.v().getClasses()) {
                for (SootMethod m: c.getMethods()) {
                    VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                    if (tag != null) {
                        for (AnnotationTag annotation : tag.getAnnotations()) {
                            if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                                js_entries.add(m);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Set<SootMethod> analysisResult = new HashSet<>();
        {
            System.out.println("Total " + js_entries.size() + " entries");
            System.out.println("Total " + js_entries_path.size() + " entries are protected by path sanitizer");
            System.out.println("Total " + js_entries_perm_0.size() + " entries are protected by perm0");
            System.out.println("Total " + js_entries_perm_1.size() + " entries are protected by perm1");

            analysisResult.clear();
            analysisResult.addAll(js_entries_perm_0);
            analysisResult.addAll(js_entries_perm_1);

            {
                System.out.println("Total " + analysisResult.size() + " entries protected by permission");
                for(SootMethod m: analysisResult){
                    System.out.println(m.toString());
                }
            }

            analysisResult.clear();
            analysisResult.addAll(js_entries);
            analysisResult.removeAll(js_entries_path);
            analysisResult.removeAll(js_entries_perm_0);
            analysisResult.removeAll(js_entries_perm_1);

            System.out.println("Total " + analysisResult.size() + " un-protected entries");
            for(SootMethod m: analysisResult){
                System.out.println(m.toString());
            }
        }
        // latex format output
        {
            List<SootMethod> js_entries_sorted = new ArrayList<>(js_entries);
            Collections.sort(js_entries_sorted,
                    new Comparator<SootMethod>()
                    {
                        public int compare(SootMethod m1, SootMethod m2)
                        {
                            return m1.toString().compareTo(m2.toString());
                        }
                    });

            System.out.println("latex format");
            int i = 1;
            for(SootMethod m: js_entries_sorted) {
                String line = String.format("%d & %s & %s & %s & %s \\\\\\hline",
                        i,
                        m.toString(),
                        js_entries_path.contains(m) ? "$\\blacksquare$" : " ",
                        js_entries_perm_0.contains(m) ? "$\\blacksquare$" : " ",
                        js_entries_perm_1.contains(m) ? "$\\blacksquare$" : " "
                );
                System.out.println(line);
                i ++;
            }
        }

        Stats.setAnalysisEnd();
        logInfo.info("Finish getting the entry.");
    }


    /*
    About Annotations:

    The visible format:
    @JSMethod(uiThread = false)

    The retrieved format:
    Visibility Annotation: level: RUNTIME (runtime-visible)
     Annotations:
    Annotation: type: Lcom/taobao/weex/annotation/JSMethod; num elems: 1 elems:
    Annotation Element: kind: Z name: uiThread value: false
     */

    Stack<SootMethod> callstack = new Stack<SootMethod>();
    private void backwardTrackEntries(
            CGHelper cgHelper,
            Set<SootMethod> entries,
            SootMethod m,
            int depth)
    {

        depth ++;
        if(depth > 20)  // to avoid cycles
        {
            this.callstack.pop();
            return;
        }

        VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
        if (tag != null) {
            for (AnnotationTag annotation : tag.getAnnotations()) {
                if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                    entries.add(m);
                }
            }
        }

        // System.out.println(depth + m.toString());

        if (m.getDeclaringClass().implementsInterface("java.lang.Runnable")) {
            for (SootMethod mt : m.getDeclaringClass().getMethods()) {
                if (mt.isConstructor()) {
                    this.callstack.push(mt);
                    this.backwardTrackEntries(cgHelper, entries, mt, depth);
                }
            }
        }

        if(cgHelper.getCallBackwardMap().containsKey(m))
        {
            for(SootMethod mt: cgHelper.getCallBackwardMap().get(m)) {
                if (mt == m) continue;
                if (mt.toString().startsWith("androidx")) continue;
                this.callstack.push(mt);
                this.backwardTrackEntries(cgHelper, entries, mt, depth);
            }
        }else
        {
//            for(SootMethod cs: this.callstack)
//            {
//                System.out.println(cs);
//            }
            entries.add(m);
        }
        this.callstack.pop();
    }
}
