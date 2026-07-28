// socket-patch CLI launcher (NuGet / .NET tool distribution).
//
// `dotnet tool install -g SocketSecurity.SocketPatch` puts `socket-patch` on
// PATH (or install repo-locally with a tool manifest and run it via
// `dotnet tool run socket-patch`). This resolves and runs the prebuilt
// `socket-patch` binary for the host platform.
//
// Strategy (mirrors scripts/install.sh's target mapping and the RubyGems /
// Composer / Maven launchers — see gem/socket-patch, composer/socket-patch,
// and maven/socket-patch):
//   1. honor SOCKET_PATCH_BIN if it points at an executable (airgap escape);
//   2. else use a cached binary under the per-user cache, keyed by
//      version + target;
//   3. else download `socket-patch-<target>.{tar.gz,zip}` from the matching
//      GitHub release, verify its SHA-256 against the release's SHA256SUMS,
//      extract the binary, cache it, and run it.
//
// MIT License — Copyright (c) Socket Security.

using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SocketSecurity.SocketPatch;

internal static class Program
{
    // Fallback version, used ONLY when the assembly's informational version
    // can't be read or isn't a plain release version (e.g. a local dev build).
    // In a real `dotnet tool install` the download uses the installed
    // package's own version — see ResolveVersion(). Kept in sync by
    // scripts/version-sync.sh.
    private const string FallbackVersion = "3.3.0";
    private const string Repo = "SocketDev/socket-patch";
    private const string Binary = "socket-patch";
    private const int MaxRedirects = 10;

    private static int Main(string[] args)
    {
        try
        {
            var bin = ResolveBinary();
            // UseShellExecute = false: run the binary directly (no shell
            // interpretation of the path or arguments) and inherit
            // stdin/stdout/stderr from this process.
            var psi = new ProcessStartInfo { FileName = bin, UseShellExecute = false };
            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }

            Process child;
            try
            {
                child = Process.Start(psi) ?? throw new LauncherException($"failed to run {bin}");
            }
            catch (Exception e) when (e is not LauncherException)
            {
                throw new LauncherException($"failed to run {bin}: {e.Message}");
            }

            using (child)
            {
                child.WaitForExit();
                return child.ExitCode;
            }
        }
        catch (LauncherException e)
        {
            Console.Error.WriteLine($"socket-patch: {e.Message}");
            return 1;
        }
    }

    private sealed class LauncherException : Exception
    {
        public LauncherException(string message) : base(message) { }
    }

    // ── binary resolution ────────────────────────────────────────────────────

    private static string ResolveBinary()
    {
        var env = Env("SOCKET_PATCH_BIN");
        if (env is not null && IsExecutableFile(env))
        {
            return env;
        }

        var ver = ResolveVersion();
        var (target, ext) = DetectTarget();
        var exe = Binary + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "");
        var cached = Path.Combine(CacheDir(), ver, target, exe);
        // Cache hit: the cached binary was SHA-256-verified when first
        // downloaded and lives under the user's own cache dir. We trust it
        // without re-verifying (re-verification would require re-fetching
        // SHA256SUMS every run), matching npx / pip / rustup; an attacker able
        // to write here can already replace the installed tool or the binary
        // itself. A cache entry that lost its exec bit fails the check and is
        // re-downloaded (self-heal), like the Ruby/PHP/Java launchers.
        if (IsExecutableFile(cached))
        {
            return cached;
        }

        DownloadBinary(ver, target, ext, cached, exe);
        return cached;
    }

    // Executability gate for the trust decisions above: on Windows existence
    // suffices (no exec bit); elsewhere require the user-execute bit so a
    // non-executable SOCKET_PATCH_BIN falls through to the normal path and a
    // mode-stripped cache entry gets re-downloaded, matching File.executable?
    // / is_executable / Files.isExecutable in the sibling launchers.
    private static bool IsExecutableFile(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        if (OperatingSystem.IsWindows())
        {
            return true;
        }
        try
        {
            return (File.GetUnixFileMode(path) & UnixFileMode.UserExecute) != 0;
        }
        catch
        {
            return false;
        }
    }

    // The version to fetch — the binary MUST match the tool package the user
    // actually installed, so derive it from the assembly's informational
    // version (the csproj pins AssemblyInformationalVersion to the package
    // version and disables the "+<git sha>" suffix) rather than trusting the
    // FallbackVersion constant (which version-sync.sh keeps current but which
    // could drift). Falls back to the constant when the attribute is missing
    // or isn't a plain major.minor.patch release (e.g. a dev/prerelease build
    // with no matching release binary).
    private static string ResolveVersion()
    {
        var info = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (info is not null)
        {
            // Strip SemVer build metadata ("3.3.0+abc123" → "3.3.0") in case a
            // build appends it despite the csproj setting.
            var plus = info.IndexOf('+');
            if (plus >= 0)
            {
                info = info[..plus];
            }
            if (Regex.IsMatch(info, @"^\d+\.\d+\.\d+$"))
            {
                return info;
            }
        }
        return FallbackVersion;
    }

    // Map the host to a release target triple + archive extension. Mirrors
    // scripts/install.sh.
    private static (string Target, string Ext) DetectTarget()
    {
        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.Arm64 => "aarch64",
            Architecture.X86 => "i686",
            Architecture.Arm => "arm",
            var other => throw new LauncherException($"unsupported CPU architecture: {other}"),
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            if (arch is not ("x86_64" or "aarch64"))
            {
                throw new LauncherException($"unsupported macOS arch: {arch}");
            }
            return ($"{arch}-apple-darwin", "tar.gz");
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var target = arch switch
            {
                "x86_64" => "x86_64-pc-windows-msvc",
                "aarch64" => "aarch64-pc-windows-msvc",
                "i686" => "i686-pc-windows-msvc",
                _ => throw new LauncherException($"unsupported Windows arch: {arch}"),
            };
            return (target, "zip");
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            var libc = IsMusl() ? "musl" : "gnu";
            var suffix = arch == "arm" ? "eabihf" : "";
            return ($"{arch}-unknown-linux-{libc}{suffix}", "tar.gz");
        }
        throw new LauncherException($"unsupported OS: {RuntimeInformation.OSDescription}");
    }

    // Alpine-style .NET builds carry "musl" in the RID; runtimes that don't
    // are caught by the musl loader at /lib/ld-musl-*.so.1 (the same probe as
    // the gem/composer launchers and scripts/install.sh).
    private static bool IsMusl()
    {
        if (RuntimeInformation.RuntimeIdentifier.Contains("musl", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        try
        {
            return Directory.GetFiles("/lib", "ld-musl-*.so.1").Length > 0;
        }
        catch
        {
            return false; // /lib missing or unreadable — assume glibc
        }
    }

    private static string CacheDir()
    {
        string baseDir;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            baseDir = Env("LOCALAPPDATA")
                ?? Path.Combine(Env("USERPROFILE") ?? HomeDir(), "AppData", "Local");
        }
        else
        {
            baseDir = Env("XDG_CACHE_HOME")
                ?? Path.Combine(Env("HOME") ?? HomeDir(), ".cache");
        }
        return Path.Combine(baseDir, "socket-patch", "bin");
    }

    /// <summary>Environment variable value, with empty treated as unset.</summary>
    private static string? Env(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static string HomeDir() =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile,
            Environment.SpecialFolderOption.DoNotVerify);

    // ── download + verify + extract ──────────────────────────────────────────

    private static void DownloadBinary(string ver, string target, string ext, string dest, string exe)
    {
        var archive = $"{Binary}-{target}.{ext}";
        var baseUrl = $"https://github.com/{Repo}/releases/download/v{ver}";

        string tmp;
        try
        {
            tmp = Directory.CreateTempSubdirectory("socket-patch-").FullName;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new LauncherException($"could not create temp dir: {e.Message}");
        }
        try
        {
            // AllowAutoRedirect = false: redirects are followed MANUALLY in
            // Fetch() so every hop's URL can be vetted as HTTPS (see HttpsUri).
            using var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(handler);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("socket-patch-dotnet");

            var archivePath = Path.Combine(tmp, archive);
            FetchToFile(client, $"{baseUrl}/{archive}", archivePath);

            var sums = FetchString(client, $"{baseUrl}/SHA256SUMS");
            VerifySha256(archivePath, archive, sums);

            Extract(archivePath, ext, tmp);
            var extracted = Path.Combine(tmp, exe);
            if (!File.Exists(extracted))
            {
                throw new LauncherException($"release archive {archive} did not contain {exe}");
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(extracted, dest, overwrite: true);
                if (!OperatingSystem.IsWindows())
                {
                    // 0755 — user rwx, group/other rx.
                    File.SetUnixFileMode(dest,
                        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                        UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new LauncherException($"could not cache binary at {dest}: {e.Message}");
            }
        }
        finally
        {
            try
            {
                Directory.Delete(tmp, recursive: true);
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }

    // Require HTTPS for every request — including after a redirect. GitHub
    // release downloads redirect to a CDN (still HTTPS); a redirect to http://
    // would let a network attacker serve a malicious binary AND a matching
    // SHA256SUMS (both attacker-controlled), defeating the checksum check. So
    // a non-HTTPS URL — initial or redirect target — is refused. (.NET's
    // auto-redirect would itself refuse an https→http downgrade, but we
    // disable it and vet each hop explicitly to match the gem/composer
    // launchers.)
    private static Uri HttpsUri(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new LauncherException($"refusing non-HTTPS URL: {url}");
        }
        return uri;
    }

    // Follow redirects manually (GitHub release downloads redirect to a CDN),
    // vetting every hop as HTTPS. Relative redirect targets are resolved
    // against the current URL; the result must still be HTTPS (see HttpsUri).
    // The caller owns (and must dispose) the returned response.
    private static HttpResponseMessage Fetch(HttpClient client, string url)
    {
        var uri = HttpsUri(url);
        for (var hop = 0; ; hop++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            HttpResponseMessage response;
            try
            {
                response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);
            }
            catch (HttpRequestException e)
            {
                throw new LauncherException($"download failed for {uri}: {e.Message}");
            }

            var status = (int)response.StatusCode;
            if (status is >= 300 and < 400 && response.Headers.Location is not null)
            {
                var location = response.Headers.Location;
                response.Dispose();
                if (hop >= MaxRedirects)
                {
                    throw new LauncherException($"too many redirects fetching {url}");
                }
                uri = HttpsUri(new Uri(uri, location).ToString());
                continue;
            }
            if (!response.IsSuccessStatusCode)
            {
                response.Dispose();
                throw new LauncherException($"download failed ({status}) for {uri}");
            }
            return response;
        }
    }

    private static void FetchToFile(HttpClient client, string url, string dest)
    {
        using var response = Fetch(client, url);
        // The headers-only Send above means the body transfers here — wrap it
        // so a dropped connection mid-download (a routine first-run failure)
        // reports "socket-patch: ..." + exit 1 instead of an unhandled
        // exception, matching the sibling launchers.
        try
        {
            using var body = response.Content.ReadAsStream();
            using var file = File.Create(dest);
            body.CopyTo(file);
        }
        catch (Exception e) when (e is IOException or HttpRequestException)
        {
            throw new LauncherException($"download failed for {url}: {e.Message}");
        }
    }

    private static string FetchString(HttpClient client, string url)
    {
        using var response = Fetch(client, url);
        try
        {
            using var body = response.Content.ReadAsStream();
            using var reader = new StreamReader(body);
            return reader.ReadToEnd();
        }
        catch (Exception e) when (e is IOException or HttpRequestException)
        {
            throw new LauncherException($"download failed for {url}: {e.Message}");
        }
    }

    // SHA256SUMS lines are "<hex>  <filename>" (some tools prefix the name
    // with `*` for binary mode); match either.
    private static void VerifySha256(string path, string archive, string sums)
    {
        string? expected = null;
        foreach (var rawLine in sums.Split('\n'))
        {
            var parts = rawLine.Trim().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }
            var name = parts[1].Trim().TrimStart('*');
            if (name == archive)
            {
                expected = parts[0].Trim();
                break;
            }
        }
        if (expected is null)
        {
            throw new LauncherException($"no SHA256SUMS entry for {archive}");
        }

        string actual;
        try
        {
            using var stream = File.OpenRead(path);
            actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new LauncherException($"could not read {path}: {e.Message}");
        }
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new LauncherException(
                $"checksum mismatch for {archive} (expected {expected}, got {actual})");
        }
    }

    // Extract without shelling out (unlike the gem/composer launchers, the BCL
    // has native zip + tar.gz support). Both ZipFile and TarFile refuse entry
    // paths that would escape the destination directory.
    private static void Extract(string archivePath, string ext, string dir)
    {
        try
        {
            if (ext == "zip")
            {
                ZipFile.ExtractToDirectory(archivePath, dir);
            }
            else
            {
                using var file = File.OpenRead(archivePath);
                using var gunzip = new GZipStream(file, CompressionMode.Decompress);
                TarFile.ExtractToDirectory(gunzip, dir, overwriteFiles: false);
            }
        }
        catch (Exception e) when (e is not LauncherException)
        {
            throw new LauncherException(
                $"failed to extract {Path.GetFileName(archivePath)}: {e.Message}");
        }
    }
}
