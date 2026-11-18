import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.Collection;

/**
 * The fixture project's only class. Maven compiles it against the
 * dependency under test, and `maven_production/mod.rs` runs it on the
 * classpath Maven resolved, so what it prints is what a build of this
 * project loads.
 *
 * Usage: Probe CLASS FIELD VALUE
 */
public class Probe {
    public static void main(String[] args) throws Exception {
        // Uses the dependency for real: the build must link against it.
        System.out.println("parsed=" + new ObjectMapper().readTree("{\"answer\":42}").get("answer").asInt());

        Class c = Class.forName(args[0]);
        System.out.println("loaded-from=" + c.getProtectionDomain().getCodeSource().getLocation().getPath());
        InputStream in = c.getClassLoader().getResourceAsStream(args[0].replace('.', '/') + ".class");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        for (int n = in.read(chunk); n >= 0; n = in.read(chunk)) {
            bytes.write(chunk, 0, n);
        }
        in.close();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
        StringBuffer hex = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hex.append(Character.forDigit((digest[i] >> 4) & 15, 16));
            hex.append(Character.forDigit(digest[i] & 15, 16));
        }
        System.out.println("class-sha256=" + hex);

        Field field = c.getDeclaredField(args[1]);
        field.setAccessible(true);
        System.out.println("probe=" + ((Collection) field.get(null)).contains(args[2]));
    }
}
