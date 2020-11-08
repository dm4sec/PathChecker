package PathChecker;

import heros.InterproceduralCFG;
import jdk.nashorn.internal.codegen.CompilerConstants;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.InvokeExprBox;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.tagkit.AnnotationTag;
import soot.tagkit.Tag;
import soot.tagkit.VisibilityAnnotationTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;
import soot.toolkits.graph.MHGPostDominatorsFinder;
import soot.toolkits.graph.UnitGraph;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class CGAnalyzer extends SceneTransformer{

    private static Logger logInfo = Logger.getLogger("CGChecker");

    InterproceduralCFG<Unit, SootMethod> icfg = null;
    CallGraph cg = null;

    Map<SootMethod, Set<SootMethod>> mref = null;

    Map<String, String> sanitizer = new HashMap<>();

    @Override
    protected void internalTransform(String s, Map<String, String> map) {


        logInfo.info("Start getting the entry.");
        Stats.setAnalysisStart();

        this.cg = Scene.v().getCallGraph();

        this.icfg = new JimpleBasedInterproceduralCFG(false, false);

        this.mref = buildRefMap();

//        this.sanitizer.put(
//                "lr",
//                "java.lang.String c(com.huawei.fastapp.core.FastSDKInstance,java.lang.String)"
//        );
//        this.sanitizer.put(
//                "com.huawei.fastapp.api.permission.DynamicPermission",
//                "java.lang.String c(com.huawei.fastapp.core.FastSDKInstance,java.lang.String)"
//        );

        SootMethod methodSanitizer = this.findMethod(
                HuaweiFastAppConfig.getSanitizer().get(0),
                HuaweiFastAppConfig.getSanitizer().get(1)
        );

        if (methodSanitizer == null)
        {
            logInfo.warning("Can't find the sanitizer.");
            return;
        }

        // this.walkCallHierarchyCG(methodSanitizer, 0);
        // this.walkCallHierarchy(methodSanitizer, 0);
        this.trace.push(methodSanitizer);
        walkRef(methodSanitizer, 0);

        System.out.println("Start listing entries.");
        System.out.println("Total " + collected_entry.size() + " entries");
        for(SootMethod m: collected_entry){
            System.out.println(m.toString());
        }
        System.out.println("Finish listing entries.");

        analyzeEntries();

        Stats.setAnalysisEnd();
        logInfo.info("Finish getting the entry.");
    }

    void analyzeEntries()
    {
        // collect all method has @JSModule tag
        // @JSMethod(uiThread = false)

        /*
        Visibility Annotation: level: RUNTIME (runtime-visible)
         Annotations:
        Annotation: type: Lcom/taobao/weex/annotation/JSMethod; num elems: 1 elems:
        Annotation Element: kind: Z name: uiThread value: false
         */

        Set<SootMethod> collected_js_entry = new HashSet<>();
        Set<SootMethod> all_js_entry = new HashSet<>();
        Set<SootMethod> analysis_result = new HashSet<>();

        for(SootMethod m: collected_entry)
        {
            VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
            if (tag != null) {
                for (AnnotationTag annotation : tag.getAnnotations()) {
                    if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                        collected_js_entry.add(m);
                        break;
                    }
                }
            }
        }

        for(SootClass c: Scene.v().getClasses()) {
            for (SootMethod m: c.getMethods()) {
                VisibilityAnnotationTag tag = (VisibilityAnnotationTag) m.getTag("VisibilityAnnotationTag");
                if (tag != null) {
                    for (AnnotationTag annotation : tag.getAnnotations()) {
                        if (annotation.getType().equals("Lcom/taobao/weex/annotation/JSMethod;")) {
                            all_js_entry.add(m);
                            break;
                        }
                    }
                }
            }
        }

        analysis_result.clear();
        analysis_result.addAll(all_js_entry);
        analysis_result.removeAll(collected_js_entry);

        System.out.println("Start listing not protected entries.");
        System.out.println("Total " + analysis_result.size() + " not protected entries");
        for(SootMethod m: analysis_result){
            System.out.println(m.toString());
        }
        System.out.println("Finish listing not protected entries.");


    }

    Stack<SootMethod> trace = new Stack<SootMethod>();
    Set<SootMethod> collected_entry = new HashSet<>();

    void walkRef(SootMethod m, int depth)
    {

        depth ++;
        if(depth > 20)  // to avoid cycles
        {
            trace.pop();
            return;
        }

        // System.out.println(depth + m.toString());

        if (m.getDeclaringClass().implementsInterface("java.lang.Runnable")) {
            for (SootMethod mt : m.getDeclaringClass().getMethods()) {
                if (mt.isConstructor()) {
                    trace.push(mt);
                    this.walkRef(mt, depth);
                }
            }
        }

        if(this.mref.containsKey(m))
        {
            for(SootMethod mr: this.mref.get(m)) {
                if (mr == m) continue;
                if (mr.toString().startsWith("androidx")) continue;
                trace.push(mr);
                this.walkRef(mr, depth);
            }
        }else
        {
            collected_entry.add(m);
//            logInfo.info("Entry: " + m.toString());
//            for (Iterator<SootMethod> it = trace.listIterator(); it.hasNext(); ) {
//                SootMethod mt = it.next();
//                System.out.println(mt.toString());
//            }
//            logInfo.info("Entry: " + m.toString());
        }
        trace.pop();
    }

    // should put this method into a standalone class
    private Map<SootMethod, Set<SootMethod>> buildRefMap()
    {
        Map<SootMethod, Set<SootMethod>> retMe = new HashMap<>();

        for(SootClass c: Scene.v().getClasses())
        {
            for(SootMethod m: c.getMethods())
            {
//                System.out.println(m.toString());
//                if(m.toString().contains("showToast"))
//                {
//                    System.out.println("x");
//                }
                Body b = null;
                try {
                    b = m.retrieveActiveBody();
                }catch(Exception e)
                {
                    // no active body
                    continue;
                }

                List<AssignStmt> assignStmts = b.getUnits().stream().filter(it -> it instanceof AssignStmt).map(it -> (AssignStmt) it).collect(Collectors.toList());

                List<SootMethodRef> refMethods = assignStmts.stream().filter(it -> it.getRightOp() instanceof InvokeExpr).map(it -> ((InvokeExpr) it.getRightOp()).getMethodRef()).collect(Collectors.toList());
                refMethods.addAll(b.getUnits().stream().filter(it -> it instanceof InvokeStmt).map(it -> ((InvokeStmt) it).getInvokeExpr().getMethodRef()).collect(Collectors.toList()));

                for (SootMethodRef refMethod: refMethods)
                {
                    SootMethod method = refMethod.resolve();
                    if(method != null && method.getDeclaringClass().isApplicationClass())
                    {
                        if(retMe.containsKey(method))
                        {
                            retMe.get(method).add(m);
                        }
                        else
                        {
                            Set<SootMethod> tmp = new HashSet<SootMethod>();
                            tmp.add(m);
                            retMe.put(method, tmp);
                        }
                    }
                    else{
                        // System.out.println(method.toString());
                    }
//                    System.out.println("-->" + refMethod.resolve());
                }

            }
        }

        return retMe;
    }


    // since no entry provided, the call graph or icfg is not reliable
    @Deprecated
    void walkCallHierarchy(SootMethod m, int depth)
    {
        depth ++;

        System.out.println(depth + m.toString());

        if(this.icfg.getCallersOf(m).size() == 0)
        {
            logInfo.info("Entry: " + m.toString());
            return;
        }

        for (Unit u: this.icfg.getCallersOf(m)) {
            SootMethod mt =this.icfg.getMethodOf(u);
            if (mt.getDeclaringClass().implementsInterface("java.lang.Runnable")) {
                for (SootMethod mr : mt.getDeclaringClass().getMethods()) {
                    if (mr.isConstructor()) {
                        // scan by myself
                        List<SootMethod> ms = findInit(mr);
                        if(ms.size() == 0)
                        {
                            logInfo.info("Entry: " + m.toString());
                            return;
                        }
                        for(SootMethod mm: ms)
                            this.walkCallHierarchy(mm, depth);
                    }
                }
            }
            this.walkCallHierarchy(mt, depth);
        }

    }

    @Deprecated
    private void walkCallHierarchyCG(SootMethod m, int depth)
    {
        depth ++;
        System.out.println(depth + m.toString());
        boolean b = this.cg.edgesInto(m).hasNext();
        if(!b)
        {
            logInfo.info("Entry: " + m.toString());
            return;
        }

        for (Iterator<Edge> it = this.cg.edgesInto(m); it.hasNext(); ) {
            Edge e = it.next();
            SootMethod mt = e.getSrc().method();
            if (mt.getDeclaringClass().implementsInterface("java.lang.Runnable")) {
                for (SootMethod mr : mt.getDeclaringClass().getMethods()) {
                    if (mr.isConstructor()) {
                        // scan by myself
                        List<SootMethod> ms = findInit(mr);
                        if(ms.size() == 0)
                        {
                            logInfo.info("Entry: " + m.toString());
                            return;
                        }
                        for(SootMethod mm: ms)
                            this.walkCallHierarchyCG(mm, depth);
                    }
                }
            }

            this.walkCallHierarchyCG(mt, depth);
        }
    }

    @Deprecated
    /* soot doesn't provide constructor connection */
    private List<SootMethod> findInit(SootMethod m)
    {
        List<SootMethod> retMe = new ArrayList<SootMethod>();

        System.out.println(m.toString());
        for(SootClass ca: Scene.v().getClasses())
        {
            for(SootMethod ma: ca.getMethods())
            {
                if(ma.hasActiveBody())
                {
                    for(Unit u: ma.getActiveBody().getUnits())
                    {
                        if(u instanceof InvokeStmt)
                        {
                            if(m == ((InvokeStmt)u).getInvokeExpr().getMethod())
                            {
                                retMe.add(ma);
                            }
                        }
                    }
                }
            }
        }
        return retMe;
    }

    private SootMethod findMethod(String c, String m)
    {
        if (Scene.v().containsClass(c)) {
            if(Scene.v().getSootClass(c).declaresMethod(m))
                return Scene.v().getSootClass(c).getMethod(m);
            else {
                for (SootMethod am: Scene.v().getSootClass(c).getMethods()) {
                    logInfo.warning("Alternative method: " + am.getSignature());
                }
                return null;
            }
        }
        else {
            for (SootClass ac: Scene.v().getClasses()) {
                // if(ac.toString().contains("lr"))
                logInfo.warning("Alternative class: " + ac.toString());
            }

            return null;
        }
    }
}
