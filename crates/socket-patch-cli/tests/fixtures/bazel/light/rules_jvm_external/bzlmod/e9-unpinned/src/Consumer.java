import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class Consumer {
  public static void main(String[] args) throws Exception {
    // The class comes from slf4j-api; the marker resource exists only in a patched jar.
    Class<?> c = org.slf4j.LoggerFactory.class;
    String state = "UNPATCHED";
    try (InputStream in = c.getResourceAsStream("/socket-patch-marker.txt")) {
      if (in != null) {
        state = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
      }
    }
    System.out.println("slf4j-api: " + state);
  }
}
