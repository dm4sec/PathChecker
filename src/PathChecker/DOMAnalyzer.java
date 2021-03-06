package PathChecker;

import heros.InterproceduralCFG;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.*;

import java.util.*;
import java.util.logging.Logger;

public class DOMAnalyzer extends SceneTransformer{
    Body wholeShadowBody = null;

    SootMethod methodSanitizer = null;
    SootMethod methodTarget = null;

    ArrayList<Unit> lstUnitSanitizers = null;
    ArrayList<Unit> lstUnitTargets = null;

    InterproceduralCFG<Unit, SootMethod> icfg = null;

    private static Logger logInfo = Logger.getLogger("DOMChecker");

    @Override
    protected void internalTransform(String s, Map<String, String> map) {
        logInfo.info("Start inflating the CFG.");
        Stats.setAnalysisStart();

        this.methodSanitizer = this.findMethod(
                HuaweiFastAppConfig.getSanitizer().get(0),
                HuaweiFastAppConfig.getSanitizer().get(1)
        );

        if (this.methodSanitizer == null)
        {
            logInfo.warning("Can't find sanitizer.");
            return;
        }

        this.methodTarget = this.findMethod(
                HuaweiFastAppConfig.getTarget().get(0),
                HuaweiFastAppConfig.getTarget().get(1)
        );

        if (this.methodTarget == null)
        {
            logInfo.warning("Can't find target.");
            return;
        }


        List<SootMethod> mEntries = Scene.v().getEntryPoints();
        // for(SootMethod m: mEntries)
        //    System.out.println(m);

        // I set only one entry
        Body bEntry = mEntries.get(0).getActiveBody();
        // this.icfg = new JimpleBasedInterproceduralCFG(false, true);
        // this.wholeShadowBody = this.collectConnectTuple(bEntry, null, null, 0);
        this.wholeShadowBody = this.collectConnectTupleCG(bEntry, null, null, 0);
        this.inflateGraph();

        BriefUnitGraph unitGraph = new BriefUnitGraph(this.wholeShadowBody);
        // EnhancedUnitGraph unitGraph = new EnhancedUnitGraph(this.wholeShadowBody);
        // ExceptionalUnitGraph
        // TrapUnitGraph

        // this.pruneGraph(unitGraph);

        this.checkDominate(unitGraph);

        Stats.setAnalysisEnd();
        logInfo.info("Finish inflating the CFG.");

        Stats.setGraphInfo(unitGraph);
        Stats.dumpGraph(unitGraph, mEntries, this.wholeShadowBody);
    }


    /*
    Collect the connection 2-tuple in advance to ensure the iterator works.
    The 2-tuples include:
    1. caller (CallStmt) -> callee
    2. ret (ExitStmt) -> post caller site (I made a copy for each method, so there is only one return site for each ExitStmt)
     */

    Map<Unit, UnitPatchingChain> callStmtWorkList = new LinkedHashMap<Unit, UnitPatchingChain>();
    Map<Unit, Unit> exitStmtWorkList = new LinkedHashMap<Unit, Unit>();

    public Body collectConnectTuple(Body body, Unit parentUnit, Unit parentUnitSucc, int depth)
    {
        depth ++;

        logInfo.info("(" + depth + ") Processing class: " + body.getMethod().getDeclaringClass().toString());
        logInfo.info("(" + depth + ") Processing method: " + body.getMethod().toString());
        // it's more reliable to use InterproceduralCFG to find the callee.
        // However, the cloned body does not contain such information.
        // Work on a clone, however reference the original ICFG.

        // Make a copy first
        Body shadowBody = (Body) body.clone();

        if(parentUnit != null)
            this.callStmtWorkList.put(parentUnit, shadowBody.getUnits());

        Iterator<Unit> units = body.getUnits().iterator();
        Iterator<Unit> shadowUnits = shadowBody.getUnits().iterator();

        while(units.hasNext())
        {
            // log but not modify the UnitPatchingChain to synchronize the traversal
            Unit unit = units.next();
            Unit shadowUnit = shadowUnits.next();

            if(unit.toString().equals(shadowUnit.toString()) == false)
            {
                logInfo.warning("Change the shadow unit scheme.");
            }

            /*
            if(unit.toString().contains("lr")) {
                logInfo.info("Walk: " + unit.toString());
                System.out.println(this.icfg.isCallStmt(unit));
            }
            INFO: Walk: $r10 = staticinvoke <lr: java.lang.String a(com.taobao.weex.WXSDKInstance,java.lang.String)>($r9, $r8)
            true
             */
            if(this.icfg.isCallStmt(unit)) {
                // System.out.println("[I]" + u.toString());
                // logInfo.info("Call stmt: " + unit.toString());
                for (SootMethod callee : this.icfg.getCalleesOfCallAt(unit)) {
                    // Since the framework APIs will inflate the graph greatly, I filter out the these APIs firstly.
                    if (callee.getDeclaringClass().isApplicationClass()) {
                        // native method?
                        // <com.facebook.imagepipeline.memory.NativeMemoryChunk: void close()>
                        if (callee.hasActiveBody() == false)
                            continue;
                        // if(true) {
                        // logInfo.info("Application class: " + callee.toString());
                        // System.out.println("[I] -> " + callee.toString());
                        /*
                        Special case:
                        $r15 = staticinvoke <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>()
                        -> <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>
                        -> <com.huawei.fastapp.core.l: void <clinit>()>

                        One anchor for two calls will make the problem complex, I take a simplified solution for this case. Should fix later.
                         */
                        if (callee.getName().contains("<clinit>"))
                            continue;

                        // empty function
                        if (this.icfg.isExitStmt(callee.getActiveBody().getUnits().getFirst()))
                            continue;

                        // recursive invocation
                        if (callee == body.getMethod()) {
                            continue;
                        }

                        /*
                        // other recursive invocation case, I build a black list to solve this problem
                        <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class)> ->
                        <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class,java.lang.reflect.Method[])>

                        <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class,java.lang.reflect.Method[])> ->
                        <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class)>
                         */

                        //                        if(callee.toString().contains("androidx.lifecycle.a: androidx.lifecycle.a$a"))
                        //                        {
                        //                            System.out.println("GOCHA");
                        //                            System.out.println(unit.getJavaSourceStartLineNumber());
                        //                            System.out.println(callee.toString());
                        //                            System.out.println(body.getMethod().toString());
                        //
                        //                        }

                        boolean bc = false;
                        for (String b : HuaweiFastAppConfig.getBlacklist()) {
                            if (callee.toString().startsWith(b)) {
                                bc = true;
                            }
                        }
                        if (bc) continue;

                        // Do not inflate the sanitizer and target node to shrink the resource consumption.
                        if (callee == this.methodSanitizer || callee == this.methodTarget) {
                            continue;
                        }
                        this.collectConnectTuple(callee.getActiveBody(), shadowUnit, shadowBody.getUnits().getSuccOf(shadowUnit), depth);
                    }
                }
            }

            if(this.icfg.isExitStmt(unit)){
                // System.out.println(unit.toString());
                if(parentUnitSucc != null)
                    this.exitStmtWorkList.put(shadowUnit, parentUnitSucc);
            }
        }
        return shadowBody;
    }

    public Body collectConnectTupleCG(Body body, Unit parentUnit, Unit parentUnitSucc, int depth)
    {
        depth ++;
        logInfo.info("(" + depth + ") Processing class: " + body.getMethod().getDeclaringClass().toString());
        logInfo.info("(" + depth + ") Processing method: " + body.getMethod().toString());

        CallGraph cg = Scene.v().getCallGraph();
        // Use call graph instead

        // Make a copy first
        Body shadowBody = (Body) body.clone();

        if(parentUnit != null)
            this.callStmtWorkList.put(parentUnit, shadowBody.getUnits());

        Iterator<Unit> units = body.getUnits().iterator();
        Iterator<Unit> shadowUnits = shadowBody.getUnits().iterator();

        while(units.hasNext())
        {
            // log but not modify the UnitPatchingChain to synchronize the traversal
            Unit unit = units.next();
            Unit shadowUnit = shadowUnits.next();

            if(unit.toString().equals(shadowUnit.toString()) == false)
            {
                logInfo.warning("Change the shadow unit scheme.");
            }

            /*
            if(unit.toString().contains("lr")) {
                logInfo.info("Walk: " + unit.toString());
                System.out.println(unit instanceof InvokeStmt);
            }
            $r10 = staticinvoke <lr: java.lang.String a(com.taobao.weex.WXSDKInstance,java.lang.String)>($r9, $r8)
            false
             */

            Iterator<Edge> iterCallees = cg.edgesOutOf(unit);
            while (iterCallees.hasNext()) {
                SootMethod callee = iterCallees.next().tgt().method();
                // Since the framework APIs will inflate the graph greatly, I filter out the these APIs firstly.
                if (callee.getDeclaringClass().isApplicationClass()) {
                    // native method?
                    // <com.facebook.imagepipeline.memory.NativeMemoryChunk: void close()>
                    if (callee.hasActiveBody() == false)
                        continue;
                    // if(true) {
                    // logInfo.info("Application class: " + callee.toString());
                    // System.out.println("[I] -> " + callee.toString());
                    /*
                    Special case:
                    $r15 = staticinvoke <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>()
                    -> <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>
                    -> <com.huawei.fastapp.core.l: void <clinit>()>

                    One anchor for two calls will make the problem complex, I take a simplified solution for this case. Should fix later.
                     */
                    if (callee.getName().contains("<clinit>"))
                        continue;

                    // empty function
                    if (callee.getActiveBody().getUnits().getFirst() instanceof ReturnStmt ||
                            callee.getActiveBody().getUnits().getFirst() instanceof ReturnVoidStmt ||
                            callee.getActiveBody().getUnits().getFirst() instanceof RetStmt
                    )
                        continue;

                    // recursive invocation
                    if (callee == body.getMethod()) {
                        continue;
                    }

                    /*
                    // other indirect recursive invocation case, I build a black list to solve this problem temporarily
                    <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class)> ->
                    <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class,java.lang.reflect.Method[])>

                    <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class,java.lang.reflect.Method[])> ->
                    <androidx.lifecycle.a: androidx.lifecycle.a$a a(java.lang.Class)>
                     */

                    boolean bc = false;
                    for (String b : HuaweiFastAppConfig.getBlacklist()) {
                        if (callee.toString().startsWith(b)) {
                            bc = true;
                        }
                    }
                    if (bc) continue;

                    // Do not inflate the sanitizer and target node to shrink the resource consumption.
                    if (callee == this.methodSanitizer || callee == this.methodTarget) {
                        continue;
                    }

                    this.collectConnectTupleCG(callee.getActiveBody(), shadowUnit, shadowBody.getUnits().getSuccOf(shadowUnit), depth);
                }
            }

            if(unit instanceof ReturnStmt ||
                    unit instanceof ReturnVoidStmt ||
                    unit instanceof RetStmt){
                    // System.out.println(unit.toString());
                if(parentUnitSucc != null)
                    this.exitStmtWorkList.put(shadowUnit, parentUnitSucc);
            }

        }
        return shadowBody;
    }

    // heuristically predict the if stmt
    // prune the useless branch
    @Deprecated
    void pruneGraph(UnitGraph unitGraph)
    {
        MHGPostDominatorsFinder mhgPostDominatorsFinder = new MHGPostDominatorsFinder(unitGraph);
        // this.wholeShadowBody.getUnits();
        for(Unit unit: this.wholeShadowBody.getUnits()) {
            if (unit instanceof IfStmt) {
                String cond = ((IfStmt) unit).getCondition().toString();
                ThrowStmt postIfThrowStmt = Jimple.v().newThrowStmt(
                        Jimple.v().newLocal("Useless branch (branch eval)",
                                RefType.v("java.lang.NullPointerException"))
                );
                if (cond.contains("== 0") || cond.contains("== null")) {
                    //((IfStmt) unit).setTarget(postIfThrowStmt);
                    for(Object ud :mhgPostDominatorsFinder.getDominators(((IfStmt) unit).getTarget()))
                        System.out.println((Unit)ud);
                } else {
                    // this.wholeShadowBody.getUnits().insertAfter(postIfThrowStmt, unit);
                }
            }
        }

    }

    // inflate the graph
    // A coarse inflation. Anyway, it works.

    // new CFG
    // caller -> entry of callee
    //                 |
    //                 v
    //   nop  <-  ret -> GotoStmt

    void inflateGraph()
    {

        for (Unit unit: this.callStmtWorkList.keySet()) {
            // System.out.println("Connect " + unit.toString() + " -> ");
            UnitPatchingChain unitPatchingChain = this.callStmtWorkList.get(unit);

            try {
//                if(unit.toString().startsWith("specialinvoke $r2.<androidx.core.view.ViewCompat$f: void <init>()>()")) {
//                    System.out.println("GOCHA");
//                }
                this.wholeShadowBody.getUnits().insertAfter(unitPatchingChain, unit);
            }catch (Exception ex) {
                logInfo.warning("Can't inflate the graph: " + unit + " -> " + unitPatchingChain);
            }
        }

        for (Unit unit: this.exitStmtWorkList.keySet()){
            // entry method
            if(this.exitStmtWorkList.get(unit) == null)
            {
                continue;
            }

            // Make an anchor for return and tail call
            NopStmt postCallNopStmt = Jimple.v().newNopStmt();
            // connect
            try {
                this.wholeShadowBody.getUnits().insertBefore(postCallNopStmt, this.exitStmtWorkList.get(unit));
            }catch (Exception ex) {
                logInfo.warning("Can't inflate the graph: " + this.exitStmtWorkList.get(unit).toString() + " -> " + postCallNopStmt.toString());
            }

            GotoStmt gotoStmt = Jimple.v().newGotoStmt(postCallNopStmt);
            try {
                this.wholeShadowBody.getUnits().insertBefore(gotoStmt, unit);
            }catch (Exception ex) {
                logInfo.warning("Can't inflate the graph: " + gotoStmt + " -> " + unit);
            }
        }
    }

    public void checkDominate(UnitGraph unitGraph)
    {
        List<Unit> lstUnitSanitizers = new ArrayList<Unit>();
        List<Unit> lstUnitTargets = new ArrayList<Unit>();

        String stringSanitizer = HuaweiFastAppConfig.getSanitizer().get(0) + ": " +
                HuaweiFastAppConfig.getSanitizer().get(1);
        String stringTarget = HuaweiFastAppConfig.getTarget().get(0) + ": " +
                HuaweiFastAppConfig.getTarget().get(1);

        // helper code snippet, for collecting soot style code
        Iterator<Unit> units = unitGraph.iterator();
//        while(units.hasNext()) {
//            Unit u = units.next();
//            System.out.println(u.toString());
//            if(u.toString().contains("c("))
//            {
//                logInfo.info("GOCHA");
//                logInfo.info("CheckDominate: " + u.toString());
//            }
//        }

        // collect sanitizer firstly
        units = unitGraph.iterator();
        while(units.hasNext()) {
            Unit u = units.next();
            if(u.toString().contains(stringSanitizer))
                lstUnitSanitizers.add(u);
        }

        // collect target
        units = unitGraph.iterator();
        while(units.hasNext()) {
            Unit u = units.next();
            if(u.toString().contains(stringTarget))
                lstUnitTargets.add(u);
        }

        if(lstUnitSanitizers.size() == 0) {
            logInfo.warning("Can't find sanitizer: " + stringSanitizer + ", adjust the sanitizer definition.");
            return;
        }
        if(lstUnitTargets.size() == 0) {
            logInfo.warning("Can't find target: " + stringTarget + ", adjust the target definition");
            return;
        }

        MHGDominatorsFinder mhgDominatorsFinder = new MHGDominatorsFinder(unitGraph);

        for(Unit unitTarget: lstUnitTargets)
        {
            for(Unit unitSanitizer: lstUnitSanitizers)
            {
                Stats.setResult(unitTarget, unitSanitizer, false);
                if(mhgDominatorsFinder.isDominatedBy(unitTarget, unitSanitizer)) {
                    Stats.setResult(unitTarget, unitSanitizer, true);
                }
            }
        }
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
