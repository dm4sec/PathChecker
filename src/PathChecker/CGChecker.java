package PathChecker;

import soot.*;
import soot.jimple.spark.SparkTransformer;
import soot.options.Options;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;


public class CGChecker {

    private static Logger logInfo = Logger.getLogger("CGChecker");

    public static void main(String[] args) {


        // retrieve the entry one by one
        List<String> entries = HuaweiFastAppConfig.getEntities();
        // System.out.println(entries);

        for (Map.Entry<String, String> entry : HuaweiFastAppConfig.getEntries().entrySet()) {
            logInfo.info("Start preparing the env.");
            Stats.setPreAnalysisStart();

            G.reset();

            // set Options
            Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_android_jars("./libs");
            // Options.v().set_src_prec(Options.src_prec_java);
            Options.v().set_process_multiple_dex(true);

            // Options.v().set_process_dir(Collections.singletonList(processDir));
            Options.v().set_process_dir(HuaweiFastAppConfig.getEntities());
            Options.v().set_whole_program(true);
            Options.v().set_allow_phantom_refs(true);
            // Options.v().set_verbose(true);
            Options.v().set_output_format(Options.output_format_none);
            Options.v().set_no_bodies_for_excluded(true);
            Options.v().setPhaseOption("cg.cha", "on");
            // Options.v().setPhaseOption("cg", "safe-newinstance:true");

            // Options.v().setPhaseOption("cg", "trim-init:false");

            // Turn off spark to enable CHA
            // Options.v().setPhaseOption("cg.spark", "on");
            // enableSpark();

            // set Scene
            Scene.v().loadNecessaryClasses();
            loadBody();
            // Scene.v().loadBasicClasses();

//            SootMethod dummyMethod = GenerateDummyClass.doGenerate(entry.getKey(), entry.getValue());
//            if(dummyMethod == null)
//                return;
//            ArrayList entryPoints = new ArrayList();
//            entryPoints.add(dummyMethod);
//            Scene.v().setEntryPoints(entryPoints);

            PackManager.v().getPack("wjtp").add(
                    new Transform("wjtp.CGChecker", new CGAnalyzer()));

            Stats.setPreAnalysisEnd();
            logInfo.info("Finish preparing the env.");

            // start packs analyse
            PackManager.v().runPacks();
        }
        Stats.dumpTimeInfo();

    }

    private static void loadBody() {
        for(SootClass c: Scene.v().getClasses()) {
            for (SootMethod m : c.getMethods()) {
                // https://mailman.cs.mcgill.ca/pipermail/soot-list/2006-January/000472.html
                if (m.hasActiveBody() == false) {
                    try {
                        m.retrieveActiveBody();
                    } catch (Exception e) {

                    }
                }
            }
        }
    }

    private static void enableSpark() {
        HashMap opt = new HashMap();
        opt.put("verbose", "true");
        opt.put("propagator", "worklist");
        opt.put("simple-edges-bidirectional", "false");
        opt.put("on-fly-cg", "true");
        opt.put("apponly", "true");
        opt.put("set-impl", "double");
        opt.put("double-set-old", "hybrid");
        opt.put("double-set-new", "hybrid");
        opt.put("enabled", "true");

        SparkTransformer.v().transform("", opt);
    }
}