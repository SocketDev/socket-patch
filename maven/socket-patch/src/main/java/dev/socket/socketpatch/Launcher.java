package dev.socket.socketpatch;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Resolves and runs the prebuilt {@code socket-patch} binary for the host
 * platform (Maven Central distribution of the socket-patch CLI).
 *
 * <p>Strategy (mirrors scripts/install.sh's target mapping and the RubyGems /
 * Composer launchers):
 * <ol>
 *   <li>honor {@code SOCKET_PATCH_BIN} if it points at an executable (airgap
 *       escape);</li>
 *   <li>else use a cached binary under the per-user cache, keyed by
 *       version + target;</li>
 *   <li>else download {@code socket-patch-<target>.{tar.gz,zip}} from the
 *       matching GitHub release, verify its SHA-256 against the release's
 *       SHA256SUMS, extract the binary, cache it, and run it.</li>
 * </ol>
 */
public final class Launcher {
    /**
     * Fallback version, used ONLY when the jar manifest's
     * Implementation-Version is unavailable (e.g. running unpacked classes
     * straight from a checkout). Kept current by scripts/version-sync.sh.
     * In a real Maven-resolved jar the download uses the jar's own stamped
     * version — see {@link #version()}.
     */
    private static final String VERSION = "3.3.0";

    private static final String REPO = "SocketDev/socket-patch";
    private static final String BINARY = "socket-patch";

    /**
     * Plain release versions look like 3.3.0 — anchored full match, because a
     * suffixed version (3.3.1-SNAPSHOT, prereleases) has no matching GitHub
     * release binary and must fall back to {@link #VERSION} instead of
     * guaranteeing a 404.
     */
    private static final Pattern RELEASE_VERSION = Pattern.compile("^\\d+\\.\\d+\\.\\d+$");

    /**
     * Follow redirects (GitHub release downloads redirect to a CDN), but only
     * to HTTPS targets: {@code Redirect.NORMAL} is documented to always
     * redirect "except from HTTPS URLs to HTTP URLs", so every hop is
     * JDK-vetted to stay on HTTPS. That matters because a redirect to
     * http:// would let a network attacker serve a malicious binary AND a
     * matching SHA256SUMS (both attacker-controlled), defeating the checksum
     * check. The initial URL is separately asserted HTTPS in
     * {@link #httpsRequest(String)}.
     */
    private static final HttpClient HTTP = buildHttpClient();

    private static HttpClient buildHttpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL);
        ProxySelector proxy = envProxySelector();
        if (proxy != null) {
            builder.proxy(proxy);
        }
        return builder.build();
    }

    /**
     * The JVM's default proxy selector only honors {@code -Dhttps.proxyHost}
     * -style system properties, never the {@code https_proxy}/{@code
     * HTTPS_PROXY} environment variables that every sibling launcher (curl in
     * install.sh, Ruby's Net::HTTP, PHP's libcurl, .NET's HttpClient) picks up
     * — so behind an env-configured egress proxy the first-run download would
     * fail only for the Maven distribution. Honor the env vars here; explicit
     * JVM proxy properties still take precedence (returning null keeps the
     * default selector, which reads them).
     */
    private static ProxySelector envProxySelector() {
        if (System.getProperty("https.proxyHost") != null
                || System.getProperty("http.proxyHost") != null) {
            return null;
        }
        for (String name : new String[] {"https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"}) {
            String value = System.getenv(name);
            if (value == null || value.isEmpty()) {
                continue;
            }
            URI uri = URI.create(value.contains("://") ? value : "http://" + value);
            if (uri.getHost() == null) {
                continue;
            }
            int port = uri.getPort() != -1
                    ? uri.getPort()
                    : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
            return ProxySelector.of(new InetSocketAddress(uri.getHost(), port));
        }
        return null;
    }

    private Launcher() {
    }

    /**
     * Entry point: resolves the platform binary, runs it with the given
     * arguments (inheriting stdio), and exits with the child's exit code.
     *
     * @param args CLI arguments passed through to the socket-patch binary
     */
    public static void main(String[] args) {
        try {
            String bin = resolveBinary();
            // Java has no exec() that replaces the process; spawn with
            // inherited stdio and propagate the child's exit status.
            List<String> cmd = new ArrayList<>();
            cmd.add(bin);
            cmd.addAll(Arrays.asList(args));
            Process child = new ProcessBuilder(cmd).inheritIO().start();
            System.exit(child.waitFor());
        } catch (LauncherError e) {
            System.err.println("socket-patch: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("socket-patch: " + e.getMessage());
            System.exit(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("socket-patch: interrupted");
            System.exit(1);
        }
    }

    /** Launcher-level failure with a user-facing message. */
    private static final class LauncherError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        LauncherError(String message) {
            super(message);
        }
    }

    // ── binary resolution ────────────────────────────────────────────────────

    private static String resolveBinary() {
        String env = System.getenv("SOCKET_PATCH_BIN");
        if (env != null && !env.isEmpty()) {
            Path p = Paths.get(env);
            if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                return env;
            }
        }

        String ver = version();
        String[] targetExt = detectTarget();
        String target = targetExt[0];
        String ext = targetExt[1];
        String exe = BINARY + (isWindows() ? ".exe" : "");
        Path cached = cacheDir().resolve(ver).resolve(target).resolve(exe);
        // Cache hit: the cached binary was SHA-256-verified when first
        // downloaded and lives under the user's own cache dir. We trust it
        // without re-verifying (re-verification would require re-fetching
        // SHA256SUMS every run), matching npx / pip / rustup; an attacker able
        // to write here can already replace the installed jar or the binary
        // itself.
        if (Files.isRegularFile(cached) && Files.isExecutable(cached)) {
            return cached.toString();
        }

        downloadBinary(ver, target, ext, cached);
        return cached.toString();
    }

    /**
     * The version to fetch — the binary MUST match the artifact the user
     * actually resolved, so derive it from the jar's own Implementation-Version
     * manifest attribute (stamped from {@code project.version} by
     * maven-jar-plugin) rather than trusting the {@code VERSION} constant
     * (which version-sync.sh keeps current but which could drift). Falls back
     * to the constant when the manifest isn't available (e.g. running unpacked
     * classes from a checkout) or reports a non-release version with no
     * matching release binary.
     */
    private static String version() {
        Package pkg = Launcher.class.getPackage();
        String v = pkg == null ? null : pkg.getImplementationVersion();
        if (v != null && RELEASE_VERSION.matcher(v).matches()) {
            return v;
        }
        return VERSION;
    }

    /**
     * Map the host to a release target triple + archive extension. Mirrors
     * scripts/install.sh.
     */
    private static String[] detectTarget() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String osArch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);

        String arch;
        if (osArch.matches(".*(x86_64|x64|amd64).*")) {
            arch = "x86_64";
        } else if (osArch.matches(".*(aarch64|arm64).*")) {
            arch = "aarch64";
        } else if (osArch.matches(".*(i[3-6]86|x86).*")) {
            arch = "i686";
        } else if (osArch.matches(".*(armv7|armhf|arm\\b).*")) {
            arch = "arm";
        } else {
            throw new LauncherError("unsupported CPU architecture: " + osArch);
        }

        // Check macOS before Windows: "darwin" contains "win".
        if (osName.contains("mac") || osName.contains("darwin")) {
            if (!arch.equals("x86_64") && !arch.equals("aarch64")) {
                throw new LauncherError("unsupported macOS arch: " + arch);
            }
            return new String[] {arch + "-apple-darwin", "tar.gz"};
        }
        if (osName.startsWith("windows")) {
            if (arch.equals("x86_64") || arch.equals("aarch64") || arch.equals("i686")) {
                return new String[] {arch + "-pc-windows-msvc", "zip"};
            }
            throw new LauncherError("unsupported Windows arch: " + arch);
        }
        if (osName.contains("linux")) {
            String libc = isMusl() ? "musl" : "gnu";
            String suffix = arch.equals("arm") ? "eabihf" : "";
            return new String[] {arch + "-unknown-linux-" + libc + suffix, "tar.gz"};
        }
        throw new LauncherError("unsupported OS: " + osName);
    }

    private static boolean isMusl() {
        try (DirectoryStream<Path> ds =
                Files.newDirectoryStream(Paths.get("/lib"), "ld-musl-*.so.1")) {
            return ds.iterator().hasNext();
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static Path cacheDir() {
        String base;
        if (isWindows()) {
            String localAppData = System.getenv("LOCALAPPDATA");
            base = (localAppData != null && !localAppData.isEmpty())
                    ? localAppData
                    : Paths.get(System.getProperty("user.home"), "AppData", "Local").toString();
        } else {
            String xdg = System.getenv("XDG_CACHE_HOME");
            base = (xdg != null && !xdg.isEmpty())
                    ? xdg
                    : Paths.get(System.getProperty("user.home"), ".cache").toString();
        }
        return Paths.get(base, "socket-patch", "bin");
    }

    // ── download + verify + extract ──────────────────────────────────────────

    private static void downloadBinary(String ver, String target, String ext, Path dest) {
        String archive = BINARY + "-" + target + "." + ext;
        String base = "https://github.com/" + REPO + "/releases/download/v" + ver;

        Path tmp;
        try {
            tmp = Files.createTempDirectory("socket-patch");
        } catch (IOException e) {
            throw new LauncherError("could not create temp dir: " + e.getMessage());
        }
        try {
            Path archivePath = tmp.resolve(archive);
            fetch(base + "/" + archive, archivePath);

            String sums = fetchString(base + "/SHA256SUMS");
            verifySha256(archivePath, archive, sums);

            extract(archivePath, ext, tmp);
            String exe = BINARY + (ext.equals("zip") ? ".exe" : "");
            Path extracted = tmp.resolve(exe);
            if (!Files.isRegularFile(extracted)) {
                throw new LauncherError("release archive " + archive + " did not contain " + exe);
            }

            try {
                Files.createDirectories(dest.getParent());
                Files.copy(extracted, dest, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new LauncherError("could not cache binary at " + dest + ": " + e.getMessage());
            }
            if (!isWindows()) {
                dest.toFile().setExecutable(true, false);
            }
        } finally {
            deleteRecursively(tmp); // best-effort temp cleanup (Ruby's mktmpdir block equivalent)
        }
    }

    /**
     * Require HTTPS for every request — including after a redirect. The
     * shared client's {@code Redirect.NORMAL} policy never follows an
     * HTTPS-to-HTTP redirect (see {@link #HTTP}); this asserts the INITIAL
     * URL is HTTPS too, so no request ever leaves over plain HTTP. A
     * non-HTTPS URL anywhere would let a network attacker serve a malicious
     * binary AND a matching SHA256SUMS (both attacker-controlled), defeating
     * the checksum check.
     */
    private static HttpRequest httpsRequest(String url) {
        if (!url.startsWith("https://")) {
            throw new LauncherError("refusing non-HTTPS URL: " + url);
        }
        return HttpRequest.newBuilder(URI.create(url)).GET().build();
    }

    private static void fetch(String url, Path dest) {
        HttpResponse<Path> res;
        try {
            res = HTTP.send(httpsRequest(url), HttpResponse.BodyHandlers.ofFile(dest));
        } catch (IOException e) {
            throw new LauncherError("download failed for " + url + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LauncherError("download interrupted for " + url);
        }
        if (res.statusCode() / 100 != 2) {
            throw new LauncherError("download failed (" + res.statusCode() + ") for " + url);
        }
    }

    private static String fetchString(String url) {
        HttpResponse<String> res;
        try {
            res = HTTP.send(httpsRequest(url), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new LauncherError("download failed for " + url + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LauncherError("download interrupted for " + url);
        }
        if (res.statusCode() / 100 != 2) {
            throw new LauncherError("download failed (" + res.statusCode() + ") for " + url);
        }
        return res.body();
    }

    /**
     * SHA256SUMS lines are {@code "<hex>  <filename>"} (some tools prefix the
     * name with {@code *} for binary mode); match either.
     */
    private static void verifySha256(Path path, String archive, String sums) {
        String expected = null;
        for (String line : sums.split("\\r?\\n")) {
            String[] parts = line.trim().split("\\s+", 2);
            if (parts.length < 2) {
                continue;
            }
            String name = parts[1].trim();
            if (name.startsWith("*")) {
                name = name.substring(1);
            }
            if (name.equals(archive)) {
                expected = parts[0];
                break;
            }
        }
        if (expected == null) {
            throw new LauncherError("no SHA256SUMS entry for " + archive);
        }
        String actual = sha256Hex(path);
        if (!actual.equalsIgnoreCase(expected)) {
            throw new LauncherError(
                    "checksum mismatch for " + archive + " (expected " + expected + ", got " + actual + ")");
        }
    }

    private static String sha256Hex(Path file) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new LauncherError("SHA-256 unavailable: " + e.getMessage());
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        } catch (IOException e) {
            throw new LauncherError("could not read " + file + ": " + e.getMessage());
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void extract(Path archivePath, String ext, Path dir) {
        if (ext.equals("zip")) {
            extractZip(archivePath, dir);
            return;
        }
        // Shell out to tar for tar.gz — the same choice as the Ruby and PHP
        // launchers: the JDK has no built-in tar support, tar ships on every
        // supported non-Windows platform, and the archive's checksum was
        // already verified against SHA256SUMS before extraction.
        try {
            Process p = new ProcessBuilder("tar", "xzf", archivePath.toString(), "-C", dir.toString())
                    .inheritIO()
                    .start();
            if (p.waitFor() != 0) {
                throw new LauncherError("failed to extract " + archivePath.getFileName());
            }
        } catch (IOException e) {
            throw new LauncherError(
                    "failed to extract " + archivePath.getFileName() + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LauncherError("failed to extract " + archivePath.getFileName() + ": interrupted");
        }
    }

    /** Zip extraction (Windows archives) with a zip-slip guard on every entry. */
    private static void extractZip(Path archivePath, Path dir) {
        Path root = dir.toAbsolutePath().normalize();
        try (ZipInputStream zin = new ZipInputStream(Files.newInputStream(archivePath))) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                // Zip-slip guard: resolve + normalize each entry path and
                // refuse anything that escapes the extraction directory.
                Path out = root.resolve(entry.getName()).normalize();
                if (!out.startsWith(root)) {
                    throw new LauncherError(
                            "refusing zip entry escaping extraction dir: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(out);
                } else {
                    if (out.getParent() != null) {
                        Files.createDirectories(out.getParent());
                    }
                    Files.copy(zin, out, StandardCopyOption.REPLACE_EXISTING);
                }
                zin.closeEntry();
            }
        } catch (IOException e) {
            throw new LauncherError(
                    "failed to extract " + archivePath.getFileName() + ": " + e.getMessage());
        }
    }

    private static void deleteRecursively(Path root) {
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        } catch (IOException ignored) {
            // best effort
        }
    }
}
