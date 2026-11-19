import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class App {
  public static void main(String[] args) throws Exception {
    // The one file of dev.socket.fixture:victim, read from the classpath.
    try (InputStream marker = App.class.getResourceAsStream("/dev/socket/fixture/victim/marker.txt")) {
      System.out.println("OUT: " + new String(marker.readAllBytes(), StandardCharsets.UTF_8).trim());
    }
  }
}
