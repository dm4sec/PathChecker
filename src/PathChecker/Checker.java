package PathChecker;

import heros.InterproceduralCFG;
import soot.*;
import soot.jimple.GotoStmt;
import soot.jimple.Jimple;
import soot.jimple.NopStmt;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.toolkits.graph.*;

import java.util.*;
import java.util.logging.Logger;

public class Checker extends SceneTransformer{
    Body body = null;

    SootMethod methodSanitizer = null;
    SootMethod methodTarget = null;

    ArrayList<Unit> lstUnitSanitizers = null;
    ArrayList<Unit> lstUnitTargets = null;

    private static Logger logInfo = Logger.getLogger("PathChecker");

    @Override
    protected void internalTransform(String s, Map<String, String> map) {
        Stat.setAnalysisStart();
        logInfo.info("Start inflating the CFG.");

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
        this.body = this.collectConnectTuple(bEntry, null, null);
        this.inflateGraph();

        BriefUnitGraph briefUnitGraph = new BriefUnitGraph(this.body);

        checkDominate(briefUnitGraph);

        logInfo.info("Finish inflating the CFG.");

        Stat.setGraphInfo(briefUnitGraph);
        Stat.dumpGraph(briefUnitGraph, mEntries, this.body);
        Stat.setAnalysisEnd();
    }


    /*
    Collect the connection 2-tuple in advance to ensure the iterator works.
    The 2-tuple include:
    1. caller (CallStmt) -> callee
    2. ret (ExitStmt) -> post caller site (I made a copy for each method, so there is only one return site for each ExitStmt)
     */

    Map<Unit, UnitPatchingChain> callStmtWorkList = new LinkedHashMap<Unit, UnitPatchingChain>();
    Map<Unit, Unit> exitStmtWorkList = new LinkedHashMap<Unit, Unit>();

    public Body collectConnectTuple(Body body, Unit parentUnit, Unit parentUnitSucc)
    {
        InterproceduralCFG<Unit, SootMethod> icfg= new JimpleBasedInterproceduralCFG(false, true);
        logInfo.info("Processing method: " + body.getMethod().toString());

        // it's more reliable to use InterproceduralCFG to find the callee.
        // However, the cloned body does not contain such information.
        // Work on a clone, however reference the original ICFG.

        // Make a copy first
        Body shadowBody = (Body) body.clone();

        if(parentUnit != null)
            this.callStmtWorkList.put(parentUnit, shadowBody.getUnits());

        Iterator<Unit> units = body.getUnits().iterator();
        Iterator<Unit> shadowUnits = shadowBody.getUnits().iterator();

        Unit unit = null;
        Unit shadowUnit = null;

        while(true)
        {
            // log but not modify the UnitPatchingChain to synchronize the traversal
            if(units.hasNext()){
                unit = units.next();
                shadowUnit = shadowUnits.next();

                if(unit.toString().equals(shadowUnit.toString()) == false)
                {
                    logInfo.warning("Change the shadow unit scheme.");
                }

                if(icfg.isCallStmt(unit)){
                    // System.out.println("[I]" + u.toString());
                    for(SootMethod callee: icfg.getCalleesOfCallAt(unit))
                    {
                        // Since the framework APIs will inflate the graph greatly, I filter out the these APIs firstly.
                        if(callee.getDeclaringClass().isApplicationClass()) {
                            // System.out.println("[I] -> " + callee.toString());
                            /*
                            Special case:
                            $r15 = staticinvoke <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>()
                            -> <com.huawei.fastapp.core.l: com.huawei.fastapp.core.l$a e()>
                            -> <com.huawei.fastapp.core.l: void <clinit>()>

                            One anchor for two calls will make the problem complex, I take a simplified solution for this case. Should fix later.
                             */
                            if(callee.getName().contains("<clinit>"))
                                continue;

                            /*
                            empty function
                             */
                            if(icfg.isExitStmt(callee.getActiveBody().getUnits().getFirst()))
                                continue;

                            /*
                            recursive invocation
                             */
                            if(callee == body.getMethod())
                            {
                                continue;
                            }

                            /*
                            Do not inflate the sanitizer and target node to shrink the resource consumption.
                             */
                            if(callee == this.methodSanitizer || callee == this.methodTarget)
                            {
                                continue;
                            }

                            collectConnectTuple(callee.getActiveBody(), shadowUnit, shadowBody.getUnits().getSuccOf(shadowUnit));
                        }
                    }
                }

                if(icfg.isExitStmt(unit)){
                    // System.out.println(unit.toString());
                    if(parentUnitSucc != null)
                        this.exitStmtWorkList.put(shadowUnit, parentUnitSucc);
                }
            }
            else{
                break;
            }
        }
        return shadowBody;
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
                this.body.getUnits().insertAfter(unitPatchingChain, unit);
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
                this.body.getUnits().insertBefore(postCallNopStmt, this.exitStmtWorkList.get(unit));
            }catch (Exception ex) {
                logInfo.warning("Can't inflate the graph: " + this.exitStmtWorkList.get(unit).toString() + " -> " + postCallNopStmt.toString());
            }

            GotoStmt gotoStmt = Jimple.v().newGotoStmt(postCallNopStmt);
            try {
                this.body.getUnits().insertBefore(gotoStmt, unit);
            }catch (Exception ex) {
                logInfo.warning("Can't inflate the graph: " + gotoStmt + " -> " + unit);
            }
        }

    }

    public void checkDominate(BriefUnitGraph unitGraph)
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
//            if(u.toString().contains("getExifFromAttributes"))
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
            logInfo.warning("Can't find sanitizer: " + stringSanitizer);
            return;
        }
        if(lstUnitTargets.size() == 0) {
            logInfo.warning("Can't find target: " + stringTarget);
            return;
        }

        MHGDominatorsFinder mhgDominatorsFinder = new MHGDominatorsFinder(unitGraph);

        for(Unit unitTarget: lstUnitTargets)
        {
            for(Unit unitSanitizer: lstUnitSanitizers)
            {
                Stat.setResult(unitTarget, unitSanitizer, false);
                if(mhgDominatorsFinder.isDominatedBy(unitTarget, unitSanitizer)) {
                    Stat.setResult(unitTarget, unitSanitizer, true);
                }
            }
        }
    }

    private SootMethod findMethod(String c, String m)
    {
        if (Scene.v().containsClass(c))
        {
            if(Scene.v().getSootClass(c).declaresMethod(m))
                return Scene.v().getSootClass(c).getMethod(m);
            else
                return null;
        }
        else
        {
            return null;
        }
    }
}
