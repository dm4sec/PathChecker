package PathChecker;

import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;


public class CGHelper {
    private static Logger logInfo = Logger.getLogger("CGHelper");

    private Map<SootMethod, Set<SootMethod>> callForwardMap = new HashMap<>();
    private Map<SootMethod, Set<SootMethod>> callBackwardMap = new HashMap<>();

    public Map<SootMethod, Set<SootMethod>> getCallForwardMap(){ return this.callForwardMap; }
    public Map<SootMethod, Set<SootMethod>> getCallBackwardMap(){ return this.callBackwardMap; }

    public CGHelper()
    {
        this.buildCallRefMap();
    }

    private void buildCallRefMap()
    {
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
                        if(this.callBackwardMap.containsKey(method))
                        {
                            this.callBackwardMap.get(method).add(m);
                        }
                        else
                        {
                            Set<SootMethod> tmp = new HashSet<SootMethod>();
                            tmp.add(m);
                            this.callBackwardMap.put(method, tmp);
                        }

                        if(this.callForwardMap.containsKey(m))
                        {
                            this.callForwardMap.get(m).add(method);
                        }
                        else
                        {
                            Set<SootMethod> tmp = new HashSet<SootMethod>();
                            tmp.add(method);
                            this.callForwardMap.put(m, tmp);
                        }

                    }
                    else{
                        // System.out.println(method.toString());
                    }
                }

            }
        }
    }

    public SootMethod findMethod(String c, String m)
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