package PathChecker;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.util.cfgcmd.CFGToDotGraph;
import soot.util.dot.DotGraph;

import java.io.IOException;
import java.util.List;

public class Stats {

    static long preAnalysisStart = 0;
    static long preAnalysisEnd = 0;
    static long analysisStart = 0;
    static long analysisEnd = 0;

    static void dumpGraph(UnitGraph unitGraph,
                          List<SootMethod> mEntries, Body body)
    {
        // For debugging.
        // time consuming, remove these codes if needed.
        // if(true)
        //     return;

        CFGToDotGraph cfgToDotGraph = new CFGToDotGraph();
        DotGraph dotGraph = cfgToDotGraph.drawCFG(unitGraph, body);

        dotGraph.plot(mEntries.get(0).getDeclaringClass().getName() + "_" + mEntries.get(0).getName() + ".dot");

        try {
            Runtime.getRuntime().exec("dot -Tpdf " +
                    mEntries.get(0).getDeclaringClass().getName() + "_" + mEntries.get(0).getName() + ".dot -o " +
                    mEntries.get(0).getDeclaringClass().getName() + "_" + mEntries.get(0).getName() + ".pdf");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void setPreAnalysisStart() { preAnalysisStart = System.currentTimeMillis();}
    static void setPreAnalysisEnd() { preAnalysisEnd = System.currentTimeMillis();}
    static void setAnalysisStart() { analysisStart = System.currentTimeMillis();}
    static void setAnalysisEnd() { analysisEnd = System.currentTimeMillis();}

    static String sanitizer = null;
    static String target = null;
    static boolean result = true;

    static void setResult(Unit t, Unit s, boolean res)
    {
        sanitizer = s.toString();
        target = t.toString();
        result = res;
    }

    static int graphSize = 0;
    static void setGraphInfo(UnitGraph unitGraph)
    {
        graphSize = unitGraph.size();
    }

    static void dumpInfo()
    {
        System.out.println("----------------------------------------------------------");
        System.out.println("Pre-analysis takes " + (preAnalysisEnd - preAnalysisStart) + " ms");
        System.out.println("Analysis takes " + (analysisEnd - analysisStart) + " ms");
        System.out.println("Total " + graphSize + " nodes in the graph");

        if (result == true)
            System.out.println("Analysis result: " + target + " is dominated by " + sanitizer);
        else
            System.out.println("Analysis result: " + target + " is NOT dominated by " + sanitizer);
        System.out.println("----------------------------------------------------------");
    }

    static void dumpTimeInfo()
    {
        System.out.println("----------------------------------------------------------");
        System.out.println("Pre-analysis takes " + (preAnalysisEnd - preAnalysisStart) + " ms");
        System.out.println("Analysis takes " + (analysisEnd - analysisStart) + " ms");
        System.out.println("----------------------------------------------------------");
    }

}
