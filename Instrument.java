import com.sun.btrace.annotations.*;
import com.sun.btrace.AnyType;
import static com.sun.btrace.BTraceUtils.*;

import java.util.Map;

@BTrace
public class Instrument {

    private static Map<String,String> classes = Collections.newHashMap();

    private static String prevClass = "main";
    static {
        println("# Compile with");
        println("# java -jar sdedit-4.01.jar classes.sd -o classes.svg -t svg");
        println("main:main===");
    }

    @OnMethod(clazz="/org\\.bouncycastle\\..*/", method="/.*/")
    public static void log(
        @ProbeClassName String probeClass,
        @ProbeMethodName String probeMethod,
        AnyType[] args) {

        if (Collections.get(classes, probeClass) == null) {
            Collections.put(classes, probeClass, probeClass);
            print(probeClass);
            print(":");
            print(probeClass);
            println("===");
        }

        print(prevClass);
        print(":response=");
        print(probeClass);
        print("---");
        print(probeMethod);
        printArray(args);

        prevClass = probeClass;
    }
}