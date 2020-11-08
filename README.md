# PathChecker 

## Introduction
The **PathChecker** is used to verify there is a sanitizer 
between the entry and the target nodes of a graph.

## How it works
Yep, it's quite simple, I use 
[*JimpleBasedInterproceduralCFG*](https://github.com/soot-oss/soot/blob/5d989a38ffa8785e395e4bed9fbbc16630d36c5b/src/main/java/soot/jimple/toolkits/ide/icfg/JimpleBasedInterproceduralCFG.java) and [*MHGDominatorsFinder*](https://www.sable.mcgill.ca/soot/doc/soot/toolkits/graph/MHGDominatorsFinder.html)
to implement this tool. By using this tool, I want to solve the problem that 
in the path from *a* to *c*, *b* dominate *c*, that's it!

## How to use this tool
1. Collect all entry nodes of an 
APK file (or a JAR file).
2. Collect all target nodes of an 
APK file (or a JAR file).
3. Collect all sanitizers.  
(all these 3 steps can be done manually or automatically.)

**Remark 1**:
When using the *JimpleBasedInterproceduralCFG*, pay special attention to the exception handler in the graph. It may violate the domination and you should check the exception handler deliberately to verify the integrity.  
**Remark 2**:
Be cautious not to dumpGraph all the time, or it will crash the application.
 
## TODO
1. There are quirks when dealing with the \<cinit\> method.
2. Since I inflate the graph (inline but not context-sensitive), the *b* may not dominate *c* anymore.
3. $r4 = <com.huawei.fastapp.utils.k: com.huawei.fastapp.commons.adapter.e b> should be splited into AssignStmt and InvokeStmt, however, it doesn't matter.  
4. **Deal with the exception in the CFG.**
5. **Shrink nodes in the CFG, remove unrelated branch, etc.**

## Reference
https://arpith.xyz/2016/05/insertonedge-soot/  
https://github.com/soot-oss/soot/wiki/Creating-a-class-from-scratch#write-to-class-file  
https://github.com/secure-software-engineering/FlowDroid/releases  
https://github.com/Sable/android-platforms  
https://www.sable.mcgill.ca/soot/tutorial/phase/phase.html