import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Loads and links every class of a jar on the JVM that runs it, then reports
 * on the classes a patch replaced. `maven_production/mod.rs` runs it once on
 * the original jar and once on the jar socket-patch put in place, on every
 * JDK it is given, and compares the two reports.
 *
 * Usage: DropIn JAR DEPENDENCIES PROBE_CLASS PROBE_FIELD PROBE_VALUE [PATCHED_CLASS...]
 *
 * DEPENDENCIES is a path-separator list of the jars JAR needs. PROBE_FIELD
 * is a static collection of PROBE_CLASS; the last line says whether it
 * holds PROBE_VALUE.
 *
 * The source is kept to what a Java 1.4 compiler accepts (no generics, no
 * autoboxing, no enhanced for), so each JDK under test compiles it itself:
 * current compilers cannot emit class files for the oldest runtimes.
 *
 * Lines that start with "# " carry detail (exception messages) and are not
 * part of the comparison.
 */
public class DropIn {
    public static void main(String[] args) throws Exception {
        String jar = args[0];
        List urls = new ArrayList();
        urls.add(new File(jar).toURI().toURL());
        String[] dependencies = split(args[1], File.pathSeparatorChar);
        for (int i = 0; i < dependencies.length; i++) {
            urls.add(new File(dependencies[i]).toURI().toURL());
        }
        // Parent: the JDK's own classes only, never this class's classpath.
        ClassLoader loader = new URLClassLoader(
                (URL[]) urls.toArray(new URL[urls.size()]),
                ClassLoader.getSystemClassLoader().getParent());

        List names = new ArrayList();
        ZipFile zip = new ZipFile(jar);
        for (Enumeration entries = zip.entries(); entries.hasMoreElements();) {
            String name = ((ZipEntry) entries.nextElement()).getName();
            if (name.endsWith(".class") && !name.startsWith("META-INF/")
                    && !name.endsWith("module-info.class")) {
                names.add(name.substring(0, name.length() - 6).replace('/', '.'));
            }
        }
        zip.close();
        Collections.sort(names);

        int linked = 0;
        for (int i = 0; i < names.size(); i++) {
            String name = (String) names.get(i);
            try {
                // Reading the members makes the JVM verify and link the class.
                Class c = Class.forName(name, false, loader);
                c.getDeclaredMethods();
                c.getDeclaredFields();
                c.getDeclaredConstructors();
                linked++;
            } catch (Throwable t) {
                System.out.println("link-fail " + name + ": " + t.getClass().getName());
                System.out.println("# " + t.getMessage());
            }
        }
        System.out.println("linked " + linked + " of " + names.size());

        for (int i = 5; i < args.length; i++) {
            try {
                Class c = Class.forName(args[i], true, loader);
                System.out.println("init " + args[i] + ": ok, from "
                        + new File(c.getProtectionDomain().getCodeSource().getLocation().getPath()).getName());
                List api = new ArrayList();
                Field[] fields = c.getDeclaredFields();
                for (int j = 0; j < fields.length; j++) {
                    if (exported(fields[j].getModifiers())) api.add(fields[j].toString());
                }
                Method[] methods = c.getDeclaredMethods();
                for (int j = 0; j < methods.length; j++) {
                    if (exported(methods[j].getModifiers())) api.add(methods[j].toString());
                }
                Constructor[] constructors = c.getDeclaredConstructors();
                for (int j = 0; j < constructors.length; j++) {
                    if (exported(constructors[j].getModifiers())) api.add(constructors[j].toString());
                }
                Collections.sort(api);
                for (int j = 0; j < api.size(); j++) {
                    System.out.println("api " + args[i] + ": " + api.get(j));
                }
            } catch (Throwable t) {
                System.out.println("init " + args[i] + ": " + t.getClass().getName());
                System.out.println("# " + t.getMessage());
            }
        }

        Class probe = Class.forName(args[2], true, loader);
        Field field = probe.getDeclaredField(args[3]);
        field.setAccessible(true);
        System.out.println("probe " + ((Collection) field.get(null)).contains(args[4]));
    }

    /** Public or protected: what code outside the package can link against. */
    private static boolean exported(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static String[] split(String list, char separator) {
        List parts = new ArrayList();
        int start = 0;
        for (int i = 0; i <= list.length(); i++) {
            if (i == list.length() || list.charAt(i) == separator) {
                if (i > start) parts.add(list.substring(start, i));
                start = i + 1;
            }
        }
        return (String[]) parts.toArray(new String[parts.size()]);
    }
}
