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

        // preserve entries to permSanitizer
        Set<SootMethod> entries_perm = new HashSet<>();
        {
            SootMethod permSanitizer = cgHelper.findMethod(
                    "com.huawei.fastapp.api.permission.DynamicPermission",
                    "boolean a(java.lang.String,java.lang.String)"
            );

            if (permSanitizer == null) {
                logInfo.warning("Can't find the sanitizer.");
                return;
            }

            this.callstack.clear();
            this.callstack.push(permSanitizer);
            this.backwardTrackEntries(cgHelper, entries_perm, permSanitizer, 0);
        }

        // preserve js entries to permSanitizer
        Set<SootMethod> js_entries_perm = new HashSet<>();
        {
            for(SootMethod m: entries_perm)
            {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            js_entries_perm.add(m);
                            break;
                        }
                    }
                }
            }
        }

        // TODO:: which permission is used to protect this entry.
        Map<SootMethod, List<String>> methodToPermMap = new HashMap<SootMethod, List<String>>();

        {
            System.out.println("Total " + js_entries_perm.size() + " entries protected by permission");
            for(SootMethod m: js_entries_perm){
                System.out.println(m.toString());
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
            analysisResult.clear();
            analysisResult.addAll(js_entries);
            analysisResult.removeAll(js_entries_path);
            analysisResult.removeAll(js_entries_perm);

            System.out.println("Total " + analysisResult.size() + " un-protected entries");
            for(SootMethod m: analysisResult){
                System.out.println(m.toString());
            }
        }

        Stats.setAnalysisEnd();
        logInfo.info("Finish getting the entry.");
    }


    private void forwardTrackPerms()
    {

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
            entries.add(m);
        }
        this.callstack.pop();
    }
}
