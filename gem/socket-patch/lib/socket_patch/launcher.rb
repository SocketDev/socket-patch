# frozen_string_literal: true

require "rbconfig"
require "digest"
require "fileutils"
require "net/http"
require "uri"
require "tmpdir"

module SocketPatch
  # Resolves and runs the prebuilt `socket-patch` binary for the host platform.
  #
  # Strategy (mirrors scripts/install.sh's target mapping):
  #   1. honor SOCKET_PATCH_BIN if it points at an executable (airgap escape);
  #   2. else use a cached binary under the per-user cache, keyed by
  #      version + target;
  #   3. else download `socket-patch-<target>.{tar.gz,zip}` from the matching
  #      GitHub release, verify its SHA-256 against the release's SHA256SUMS,
  #      extract the binary, cache it, and run it.
  module Launcher
    # Fallback version, used ONLY when the installed gem's version can't be read
    # (e.g. running this file from a checkout). In a real `gem install` the
    # download uses the installed gem's own version — see `version`.
    VERSION = "3.3.0"
    REPO = "SocketDev/socket-patch"
    BINARY = "socket-patch"

    module_function

    def run(argv)
      bin = resolve_binary
      if Gem.win_platform?
        # Windows has no exec() that replaces the process cleanly for console
        # apps; spawn + wait and propagate the child's exit status.
        exit(system(bin, *argv) ? $?.exitstatus : 1)
      else
        exec([bin, bin], *argv)
      end
    rescue LauncherError => e
      warn("socket-patch: #{e.message}")
      exit(1)
    end

    class LauncherError < StandardError; end

    # ── binary resolution ─────────────────────────────────────────────────────

    def resolve_binary
      env = ENV["SOCKET_PATCH_BIN"]
      return env if env && !env.empty? && File.executable?(env)

      ver = version
      target, ext = detect_target
      exe = BINARY + (Gem.win_platform? ? ".exe" : "")
      cached = File.join(cache_dir, ver, target, exe)
      return cached if File.executable?(cached)

      download_binary(ver, target, ext, cached)
      cached
    end

    # The version to fetch — the binary MUST match the CLI package the user
    # actually installed, so derive it from the installed gem's own spec rather
    # than trusting the `VERSION` constant (which `version-sync.sh` keeps current
    # but which could drift). Falls back to the constant when the gem isn't
    # activated (e.g. running this file directly from a checkout).
    def version
      if (spec = Gem.loaded_specs["socket-patch"])
        return spec.version.to_s
      end
      Gem::Specification.find_by_name("socket-patch").version.to_s
    rescue StandardError
      VERSION
    end

    # Map the host to a release target triple + archive extension. Mirrors
    # scripts/install.sh.
    def detect_target
      host_os = RbConfig::CONFIG["host_os"].downcase
      host_cpu = RbConfig::CONFIG["host_cpu"].downcase

      arch =
        case host_cpu
        when /x86_64|x64|amd64/ then "x86_64"
        when /aarch64|arm64/ then "aarch64"
        when /i[3-6]86|x86/ then "i686"
        when /armv7|armhf|arm\b/ then "arm"
        else raise LauncherError, "unsupported CPU architecture: #{host_cpu}"
        end

      case host_os
      when /darwin|mac/
        raise LauncherError, "unsupported macOS arch: #{arch}" unless %w[x86_64 aarch64].include?(arch)
        ["#{arch}-apple-darwin", "tar.gz"]
      when /mswin|mingw|cygwin|windows/
        win =
          case arch
          when "x86_64" then "x86_64-pc-windows-msvc"
          when "aarch64" then "aarch64-pc-windows-msvc"
          when "i686" then "i686-pc-windows-msvc"
          else raise LauncherError, "unsupported Windows arch: #{arch}"
          end
        [win, "zip"]
      when /linux/
        libc = musl? ? "musl" : "gnu"
        suffix = arch == "arm" ? "eabihf" : ""
        ["#{arch}-unknown-linux-#{libc}#{suffix}", "tar.gz"]
      else
        raise LauncherError, "unsupported OS: #{host_os}"
      end
    end

    def musl?
      return true if RbConfig::CONFIG["host_os"].downcase.include?("musl")
      Dir.glob("/lib/ld-musl-*.so.1").any?
    rescue StandardError
      false
    end

    def cache_dir
      base =
        if Gem.win_platform?
          ENV["LOCALAPPDATA"] || File.join(Dir.home, "AppData", "Local")
        else
          ENV["XDG_CACHE_HOME"] || File.join(Dir.home, ".cache")
        end
      File.join(base, "socket-patch", "bin")
    end

    # ── download + verify + extract ───────────────────────────────────────────

    def download_binary(ver, target, ext, dest)
      archive = "#{BINARY}-#{target}.#{ext}"
      base = "https://github.com/#{REPO}/releases/download/v#{ver}"

      Dir.mktmpdir("socket-patch") do |tmp|
        archive_path = File.join(tmp, archive)
        fetch("#{base}/#{archive}", archive_path)

        sums = fetch_string("#{base}/SHA256SUMS")
        verify_sha256!(archive_path, archive, sums)

        extract(archive_path, ext, tmp)
        exe = BINARY + (ext == "zip" ? ".exe" : "")
        extracted = File.join(tmp, exe)
        unless File.file?(extracted)
          raise LauncherError, "release archive #{archive} did not contain #{exe}"
        end

        FileUtils.mkdir_p(File.dirname(dest))
        FileUtils.cp(extracted, dest)
        File.chmod(0o755, dest) unless Gem.win_platform?
      end
    end

    # Follow redirects (GitHub release downloads redirect to a CDN) and stream
    # the body to `dest`.
    def fetch(url, dest, redirects = 10)
      raise LauncherError, "too many redirects fetching #{url}" if redirects.zero?
      uri = URI(url)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
        http.request(Net::HTTP::Get.new(uri)) do |res|
          case res
          when Net::HTTPRedirection
            return fetch(res["location"], dest, redirects - 1)
          when Net::HTTPSuccess
            File.open(dest, "wb") { |f| res.read_body { |chunk| f.write(chunk) } }
          else
            raise LauncherError, "download failed (#{res.code}) for #{url}"
          end
        end
      end
    end

    def fetch_string(url, redirects = 10)
      raise LauncherError, "too many redirects fetching #{url}" if redirects.zero?
      uri = URI(url)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
        http.request(Net::HTTP::Get.new(uri))
      end
      case res
      when Net::HTTPRedirection then fetch_string(res["location"], redirects - 1)
      when Net::HTTPSuccess then res.body
      else raise LauncherError, "download failed (#{res.code}) for #{url}"
      end
    end

    # SHA256SUMS lines are "<hex>  <filename>" (some tools prefix the name
    # with `*` for binary mode); match either.
    def verify_sha256!(path, archive, sums)
      expected = nil
      sums.each_line do |line|
        hex, name = line.split(/\s+/, 2)
        next unless name
        name = name.strip.sub(/\A\*/, "")
        if name == archive
          expected = hex.strip
          break
        end
      end
      raise LauncherError, "no SHA256SUMS entry for #{archive}" unless expected
      actual = Digest::SHA256.file(path).hexdigest
      return if actual.casecmp?(expected)
      raise LauncherError, "checksum mismatch for #{archive} (expected #{expected}, got #{actual})"
    end

    def extract(archive_path, ext, dir)
      ok =
        if ext == "zip"
          # bsdtar (the `tar` on modern Windows) extracts zip; fall back to
          # PowerShell Expand-Archive.
          system("tar", "-xf", archive_path, "-C", dir) ||
            system("powershell", "-NoProfile", "-Command",
                   "Expand-Archive -Force -LiteralPath '#{archive_path}' -DestinationPath '#{dir}'")
        else
          system("tar", "xzf", archive_path, "-C", dir)
        end
      raise LauncherError, "failed to extract #{File.basename(archive_path)}" unless ok
    end
  end
end
