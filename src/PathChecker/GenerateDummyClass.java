package PathChecker;

import soot.Modifier;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.entryPointCreators.SequentialEntryPointCreator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class GenerateDummyClass {
    private static Logger logInfo = Logger.getLogger("PathChecker");

    static SootMethod doGenerate(String classNameSignature, String methodSignature)
    {
        SootClass sc = Scene.v().loadClassAndSupport(classNameSignature);
        sc.setApplicationClass();

        if (sc.declaresMethod(methodSignature) == false)
        {
            logInfo.warning("Cannot find method: " + methodSignature);
            logInfo.warning("Alternative methods list:");

            for (SootMethod m: sc.getMethods())
                logInfo.warning(m.toString());
            return null;
        }

        // invoke soot to generate a dummy method
        List<String> e = new ArrayList<String>();
        e.add("<" + classNameSignature + ": " + methodSignature + ">");
        SequentialEntryPointCreator sequentialEntryPointCreator = new SequentialEntryPointCreator(e);
        SootMethod m = sequentialEntryPointCreator.createDummyMain();

        return m;
    }
}
