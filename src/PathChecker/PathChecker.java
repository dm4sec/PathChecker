package PathChecker;

import soot.*;
import soot.jimple.spark.SparkTransformer;
import soot.options.Options;

import java.util.*;
import java.util.logging.Logger;


public class PathChecker {

    private static Logger logInfo = Logger.getLogger("PathChecker");

    public static void main(String[] args) {


        Stat.setPreAnalysisStart();
        logInfo.info("Start verifying the path.");

        // retrieve the entry one by one
        List<String> entries = HuaweiFastAppConfig.getEntities();
        // System.out.println(entries);

        for (Map.Entry<String, String> entry : HuaweiFastAppConfig.getEntries().entrySet()) {
            logInfo.info("Setting entry, class: " + entry.getKey() + ", method: " + entry.getValue());

            soot.G.reset();

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
            Options.v().setPhaseOption("cg.spark", "on");
            Options.v().set_no_bodies_for_excluded(true);
            // Options.v().set_app(true);
            enableSpark();

            // set Scene
            Scene.v().loadNecessaryClasses();
            Scene.v().loadBasicClasses();

            if (loadClass(entry.getKey(), entry.getValue()) == false)
                continue;

            PackManager.v().getPack("wjtp").add(
                    new Transform("wjtp.DomChecker", new Checker()));

            Stat.setPreAnalysisEnd();

            // start packs analyse
            PackManager.v().runPacks();

        }
        logInfo.info("Finish verifying the path.");
        Stat.dumpInfo();

    }

    // TODO:: Set in a batch mode? (if the call graph inflate will not change the relationship.)
    private static boolean loadClass(String classNameSignature, String methodSignature) {
        SootClass c = Scene.v().loadClassAndSupport(classNameSignature);
        c.setApplicationClass();

//        for(SootClass cc: Scene.v().getApplicationClasses())
//        {
//            logInfo.info(cc.toString());
//        }

        if (c.declaresMethod(methodSignature) == false)
        {
            logInfo.warning("Cannot find method: " + methodSignature);
            logInfo.warning("Alternative methods list:");

            for (SootMethod m: c.getMethods())
                logInfo.warning(m.toString());
            return false;
        }

        // Scene.v().setMainClass(c);
        SootMethod m = c.getMethod(methodSignature);
        // SootMethod m = c.getMethodByName();
        ArrayList entryPoints = new ArrayList();
        entryPoints.add(m);
        Scene.v().setEntryPoints(entryPoints);

        return true;
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