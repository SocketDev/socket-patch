#!/usr/bin/env ruby
# frozen_string_literal: true

# End-to-end test of agent-mode patches to a real nokogiri install.
#
# nokogiri is the gem agent mode has the most ways to get wrong: since 1.11
# Bundler installs a precompiled platform gem with one binary per Ruby minor,
# before that (and on any Ruby a precompiled gem does not cover) RubyGems
# compiles it together with a vendored libxml2 and libxslt, and a third of
# the patches Socket publishes for it change nothing but a patch file of that
# vendored libxml2. This script installs one nokogiri release with the real
# Bundler, lays hand-built patch records over it with the real `socket-patch`
# binary, and checks what the Ruby of that install then loads.
#
# It is one Ruby file with no gem dependencies, so it runs wherever the
# install under test runs: a GitHub runner, an Alpine or a ten year old
# Debian container, Windows, JRuby. Ruby 2.1 is the floor (RubyGems 2.2, the
# oldest `socket-patch` rebuilds an extension with), so no syntax newer than
# that is used here.
#
# The records are the three shapes of the published nokogiri patches:
#
#   ruby     a change to `lib/nokogiri.rb`. Ruby loads it as it is, so
#            nothing is built.
#   c        a change to `ext/nokogiri/nokogiri.c`. It takes effect only in
#            a rebuilt extension.
#   libxml2  a new `patches/libxml2/*.patch` (`ports/patches/libxml2` before
#            1.6.7). nokogiri's build applies it to its vendored libxml2 and
#            compiles the patch's name into the extension. An install built
#            with `--use-system-libraries` compiles no vendored libxml2, so
#            there the patch is incomplete: the record's file is written
#            and stays written, `apply` fails (exit 1) and says that
#            nothing compiles it, and nothing attests it.
#
# Each scenario runs `apply --check` (not in sync), `apply`, a load of
# nokogiri through `bundle exec` in a fresh Ruby, `apply --check` (in sync),
# `apply` again (nothing to do), `vex` and `rollback`, and then compares
# every file of the gem home with the install it started from.
#
# JRuby installs nokogiri's `java` platform gem, which runs jars and has no
# C extension and no libxml2. It takes of a record what is part of that
# build, and nothing is built there:
#
#   ruby     applied, as on any Ruby.
#   c        the `java` gem ships the C sources too (nothing compiles them),
#            so the file is written and the patch is in sync and attested;
#            JRuby loads no C constant and the jars it loaded before.
#   libxml2  the `java` gem has no libxml2 patch directory: no file of the
#            record is part of it. `apply` exits 0, writes nothing and says
#            so, and the install is in sync and attested: the code the
#            patch fixes is not in that build.
#
#   ruby tests/nokogiri/nokogiri_e2e.rb --socket-patch target/debug/socket-patch \
#     --nokogiri 1.18.10 --install precompiled
#
# `--help` lists the options. Exit status 0 means every check passed.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "tmpdir"

RB_CONST = "SOCKET_PATCH_E2E_RB"
C_CONST = "SOCKET_PATCH_E2E_C"
LIBXML2_PATCH = "0100-socket-patch-e2e.patch"
UUID = "0e2e0e2e-0e2e-4e2e-8e2e-0e2e0e2e0e2e"
GHSA = "GHSA-e2e0-e2e0-e2e0"
PRODUCT = "pkg:generic/socket-patch-nokogiri-e2e"

# A diff that adds one file. It applies to every libxml2 release, with `git
# apply` and with `patch -p1` (mini_portile uses whichever it finds).
LIBXML2_PATCH_BODY = [
  "diff --git a/socket-patch-e2e.txt b/socket-patch-e2e.txt",
  "new file mode 100644",
  "--- /dev/null",
  "+++ b/socket-patch-e2e.txt",
  "@@ -0,0 +1 @@",
  "+Added by the socket-patch nokogiri end-to-end test.",
  ""
].join("\n")

class Failure < StandardError; end

class NokogiriE2E
  def initialize(opts)
    @opts = opts
    @bin = File.expand_path(opts.fetch(:socket_patch))
    @version = opts.fetch(:nokogiri)
    @checks = 0
  end

  def run
    @bin += ".exe" if !File.file?(@bin) && File.file?(@bin + ".exe")
    raise Failure, "no socket-patch binary at #{@bin}" unless File.file?(@bin)
    root = @opts[:work] ? File.expand_path(@opts[:work]) : Dir.mktmpdir("nokogiri-e2e-")
    FileUtils.mkdir_p(root)
    # The project path Ruby and the CLI are given has no symlink in it:
    # macOS hands out its temp dir through one.
    @proj = File.join(File.realpath(root), "project")
    begin
      FileUtils.rm_rf(@proj)
      FileUtils.mkdir_p(@proj)
      install
      @baseline = probe
      @pristine = snapshot
      describe_install
      @opts.fetch(:scenarios).each { |name| scenario(name) }
      puts "PASS: #{@checks} checks on nokogiri #{@version} (#{@shape}), #{ruby_label}"
    ensure
      FileUtils.rm_rf(root) unless @opts[:work]
    end
  end

  private

  def ruby_label
    "#{RUBY_ENGINE} #{RUBY_VERSION} on #{RUBY_PLATFORM}"
  end

  # ---- running things ----------------------------------------------------

  # What every child runs with. The Ruby under test comes first on PATH,
  # and nothing of the Ruby that runs this script is passed on. With
  # `--gem-home project` Bundler is configured by the project alone; with
  # `--gem-home ambient` the environment's own Bundler and RubyGems
  # settings stay, since they are what is under test (an official Ruby
  # image sets GEM_HOME, BUNDLE_APP_CONFIG and BUNDLE_PATH).
  def base_env
    env = {
      "RUBYOPT" => nil, "RUBYLIB" => nil,
      "BUNDLE_GEMFILE" => File.join(@proj, "Gemfile"),
      "BUNDLE_BIN_PATH" => nil, "BUNDLER_VERSION" => nil,
      "BUNDLE_FROZEN" => nil, "BUNDLE_DEPLOYMENT" => nil, "BUNDLE_WITHOUT" => nil,
      "NOKOGIRI_USE_SYSTEM_LIBRARIES" => nil,
      "PATH" => [RbConfig::CONFIG["bindir"], ENV["PATH"]].join(File::PATH_SEPARATOR)
    }
    if project_home?
      env.update("BUNDLE_APP_CONFIG" => File.join(@proj, ".bundle"), "BUNDLE_PATH" => nil,
                 "BUNDLE_BIN" => nil, "BUNDLE_FORCE_RUBY_PLATFORM" => nil)
      ENV.each_key { |k| env[k] = nil if k.start_with?("BUNDLE_BUILD__") }
    end
    env
  end

  def project_home?
    @opts.fetch(:gem_home) == "project"
  end

  def sh(env, *cmd)
    out, status = Open3.capture2e(base_env.merge(env), *cmd, :chdir => @proj)
    [status.exitstatus || -1, out]
  end

  def sh!(env, *cmd)
    code, out = sh(env, *cmd)
    raise Failure, "`#{cmd.join(' ')}` exited #{code}:\n#{tail(out)}" unless code.zero?
    out
  end

  def bundle(*args)
    [RbConfig.ruby, "-S", "bundle", *args]
  end

  def tail(text, lines = 60)
    all = text.to_s.lines
    (all.size > lines ? ["... (#{all.size - lines} lines above)\n"] : []).concat(all.last(lines)).join
  end

  # The CLI, as a CI job runs it: no saved login, no update check, and with
  # `--hide-toolchain` the PATH this script was started with stripped of every
  # directory that holds a compiler (see `strip_toolchain`).
  def sp(*args)
    env = {
      "SOCKET_NO_CONFIG" => "1", "SOCKET_NO_API_TOKEN" => "1",
      "SOCKET_NO_UPDATE_CHECK" => "1", "SOCKET_TELEMETRY_DISABLED" => "1"
    }
    env["PATH"] = strip_toolchain(base_env["PATH"]) if @opts[:hide_toolchain]
    started = Time.now
    out, err, status = Open3.capture3(base_env.merge(env), @bin, *args, :chdir => @proj)
    [status.exitstatus || -1, out, err, Time.now - started]
  end

  # PATH without the directories that hold a C compiler or `make`, except
  # the Ruby's own. For a machine that has a toolchain, to see what a
  # machine without one gets.
  def strip_toolchain(path)
    keep = RbConfig::CONFIG["bindir"]
    exts = RbConfig::CONFIG["EXEEXT"].to_s.empty? ? [""] : ["", RbConfig::CONFIG["EXEEXT"]]
    tools = %w[cc gcc clang make gmake]
    path.split(File::PATH_SEPARATOR).reject do |dir|
      next false if dir == keep
      tools.any? { |t| exts.any? { |e| File.file?(File.join(dir, t + e)) } }
    end.join(File::PATH_SEPARATOR)
  end

  def check(ok, what, detail = nil)
    @checks += 1
    return puts("  ok   #{what}") if ok
    raise Failure, ["FAILED: #{what}", detail].compact.join("\n")
  end

  # ---- the install -------------------------------------------------------

  # A `bundle install` failure that may be the registry's and not a result:
  # the install is tried again. (Not "HTTP": Bundler names
  # https://rubygems.org in every failure.)
  #
  # The last pattern is not a network error by its text. Bundler reads which
  # Rubies and which RubyGems a release supports from the compact index.
  # When one request to that index fails, Bundler does not fail: it resolves
  # from the full index instead, which lists names and versions only, takes
  # the newest release of every gem, and stops at the first one this Ruby
  # cannot run:
  #
  #   minitest-5.27.0 requires ruby version >= 3.1, which is incompatible
  #   with the current version, ruby 2.3.8p459
  #
  # (Bundler 2 words it "requires Ruby version >= 3.2. The current ruby
  # version is 3.1.6.") It writes no lock, so the next try resolves anew.
  # A requirement the Gemfile really cannot meet fails every try.
  REGISTRY_BLIP = Regexp.union(
    /Network error|Gem::RemoteFetcher::FetchError|Net::(?:Open|Read)Timeout|Could not (?:reach|fetch)/,
    /requires ruby(?:gems)? version/i
  )

  # `bundle install` in the project, up to three times while it fails the
  # way a registry failure does. Returns the exit code and the output of
  # the last try.
  def bundle_install(env = {})
    attempts = 0
    loop do
      attempts += 1
      code, out = sh(env, *bundle("install", "--jobs", "4", "--retry", "3"))
      return [code, out] if code.zero? || attempts >= 3 || out !~ REGISTRY_BLIP
      puts "  `bundle install` failed, maybe on a registry failure: installing again, attempt #{attempts + 1} of 3",
           "    #{out.lines.grep(REGISTRY_BLIP).first.to_s.strip}"
      sleep(5 * attempts)
    end
  end

  def bundle_install!(env = {})
    code, out = bundle_install(env)
    raise Failure, "`bundle install` exited #{code}:\n#{tail(out)}" unless code.zero?
    out
  end

  def install
    gemfile = ["source \"https://rubygems.org\"", "gem \"nokogiri\", \"#{@version}\""]
    if @opts[:rails]
      gemfile << "gem \"rails\", \"#{@opts[:rails]}\""
      # loofah 2.20 and later need `Nokogiri::HTML4` (nokogiri 1.12) while
      # still declaring `nokogiri >= 1.5.9`, so a fresh resolve gives an
      # older nokogiri a loofah that cannot load on it. A lock of those
      # years holds the loofah and the sanitizer of those years.
      if Gem::Version.new(@version) < Gem::Version.new("1.12")
        gemfile << "gem \"loofah\", \"< 2.20\"" << "gem \"rails-html-sanitizer\", \"< 1.5\""
      end
    end
    (@opts[:gems] || []).each { |line| gemfile << line }
    File.write(File.join(@proj, "Gemfile"), gemfile.join("\n") + "\n")
    want = @opts.fetch(:install)
    settings = {}
    settings["BUNDLE_PATH"] = "vendor/bundle" if project_home?
    settings["BUNDLE_FORCE_RUBY_PLATFORM"] = "true" if %w[source system-libraries].include?(want)
    settings["BUNDLE_BUILD__NOKOGIRI"] = "--use-system-libraries" if want == "system-libraries"
    (@opts[:settings] || []).each do |pair|
      key, value = pair.split("=", 2)
      settings[key] = value.to_s
    end
    if project_home?
      FileUtils.mkdir_p(File.join(@proj, ".bundle"))
      lines = settings.map { |k, v| "#{k}: \"#{v}\"" }
      File.write(File.join(@proj, ".bundle", "config"), (["---"] + lines).join("\n") + "\n")
      @install_env = {}
    else
      # The ambient configuration is not this script's to write: the
      # settings ride on the install's environment instead.
      @install_env = settings
    end

    puts "Installing nokogiri #{@version} (#{want}) with #{sh!({}, *bundle('--version')).strip}, #{ruby_label}"
    bundle_install!(@install_env)

    # The copy Bundler loads, wherever this environment keeps its gems.
    where = sh!({}, *bundle("exec", RbConfig.ruby, "-e",
                            "puts 'sp_gem_dir\t' + Gem.loaded_specs.fetch('nokogiri').full_gem_path"))
    line = where.lines.grep(/\Asp_gem_dir\t/).last
    raise Failure, "Bundler did not say where nokogiri is installed:\n#{tail(where)}" unless line
    @gem_dir = File.realpath(line.split("\t", 2).last.strip)
    @home = File.dirname(File.dirname(@gem_dir))
    unless File.basename(File.dirname(@gem_dir)) == "gems" && File.directory?(File.join(@home, "specifications"))
      raise Failure, "#{@gem_dir} is not in a RubyGems gem home"
    end
    inside = @gem_dir.start_with?(@proj + File::SEPARATOR)
    raise Failure, "nokogiri was installed at #{@gem_dir}, not in the project" if project_home? && !inside
    @full_name = File.basename(@gem_dir)
    unless @full_name.start_with?("nokogiri-#{@version}")
      raise Failure, "Bundler loads #{@full_name}, not nokogiri #{@version}"
    end
    platform = @full_name.sub("nokogiri-#{@version}", "").sub(/\A-/, "")
    @java = platform == "java"
    @precompiled = !platform.empty? && !@java

    File.write(File.join(@proj, "probe.rb"), PROBE)
  end

  def describe_install
    lib = @baseline["libxml_source"]
    @shape = if @java then "java"
             elsif @precompiled then "precompiled"
             elsif lib == "system" then "system-libraries"
             else "source"
             end
    loads = @java ? "#{@baseline['jars'].size} jars" : (@baseline["binary"] || "no native binary")
    puts "Installed #{@full_name}: #{@shape}, libxml2 #{@baseline['libxml_loaded']} (#{lib}), " \
         "#{@baseline['libxml_patches'].size} libxml2 patches, loads #{loads}"
    if @opts[:rails]
      puts "Rails #{@baseline['rails']} boots and sanitizes HTML through it: #{@baseline['rails_sanitize'].inspect}"
      check(@baseline["rails"].to_s.start_with?(@opts[:rails].sub(/\A[^0-9]*/, "")[/\A\d+\.\d+/]),
            "the bundle holds Rails #{@opts[:rails]}", "it holds #{@baseline['rails']}")
      clean = @baseline["rails_sanitize"].to_s
      check(clean.start_with?("<p>ok") && clean !~ /onclick|<script/i, "Rails sanitizes HTML with this nokogiri",
            clean.inspect)
    end
    want = @opts.fetch(:install)
    check(want == "any" || want == @shape, "the install is #{want}", "it is #{@shape}: #{@full_name}")
    if @java
      check(@baseline["jars"].keys.include?("nokogiri.jar") && @baseline["binary"].nil?,
            "JRuby loads nokogiri's jars and no C extension", @baseline["jars"].keys.inspect)
    end
    check(@baseline[RB_CONST].nil? && @baseline[C_CONST].nil?, "a fresh install carries no test marker")
    check(leftovers.empty?, "a fresh install holds nothing of socket-patch", leftovers.inspect)
  end

  # What a fresh Ruby loads through Bundler, as an application would.
  def probe
    out = sh!({}, *bundle("exec", RbConfig.ruby, "probe.rb", *(@opts[:rails] ? ["--rails"] : [])))
    line = out.lines.grep(/\Asp_probe\t/).last
    raise Failure, "the probe printed no result:\n#{tail(out)}" unless line
    JSON.parse(line.split("\t", 2).last)
  end

  # relative path => digest of every file of the nokogiri install: its gem
  # dir, its spec, its built extension and its recorded build arguments.
  def snapshot
    files = {}
    roots = [@gem_dir, File.join(@home, "specifications"), File.join(@home, "extensions"),
             File.join(@home, "build_info")]
    roots.each do |root|
      next unless File.exist?(root)
      Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH).each do |path|
        next unless File.file?(path) && !File.symlink?(path)
        rel = path[(@home.size + 1)..-1]
        next if rel.start_with?("specifications/") && rel !~ %r{\Aspecifications/nokogiri-}
        next if rel.start_with?("extensions/") && rel !~ %r{/nokogiri-[^/]+/}
        next if rel.start_with?("build_info/") && rel !~ %r{\Abuild_info/nokogiri-}
        files[rel] = Digest::SHA256.file(path).hexdigest
      end
    end
    files
  end

  # Entries socket-patch keeps in a gem home or gem dir while a native patch
  # is applied; none may outlive a rollback.
  def leftovers
    found = Dir.glob(File.join(@home, ".socket-patch*"), File::FNM_DOTMATCH)
    found.concat(Dir.glob(File.join(@gem_dir, ".socket-patch*"), File::FNM_DOTMATCH))
    found.concat(Dir.glob(File.join(@home, "extensions", "**", "*.socket-patch*"), File::FNM_DOTMATCH))
    found.map { |p| p[(@home.size + 1)..-1] }
  end

  def tree_diff(now)
    keys = (@pristine.keys + now.keys).uniq.sort
    keys.map do |k|
      if !@pristine.key?(k) then "added    #{k}"
      elsif !now.key?(k) then "missing  #{k}"
      elsif @pristine[k] != now[k] then "changed  #{k}"
      end
    end.compact
  end

  # ---- the records -------------------------------------------------------

  def git_sha256(bytes)
    Digest::SHA256.hexdigest("blob #{bytes.bytesize}\0".b + bytes.b)
  end

  def purl
    "pkg:gem/nokogiri@#{@version}?platform=ruby"
  end

  # Writes `.socket/manifest.json` and the blobs of one record. `files` maps
  # a path in the gem to [content before or nil, content after].
  def write_record(files)
    socket = File.join(@proj, ".socket")
    FileUtils.rm_rf(socket)
    FileUtils.mkdir_p(File.join(socket, "blobs"))
    entries = {}
    files.each do |path, (before, after)|
      [before, after].compact.each do |bytes|
        File.binwrite(File.join(socket, "blobs", git_sha256(bytes)), bytes)
      end
      entries[path] = { "beforeHash" => before ? git_sha256(before) : "", "afterHash" => git_sha256(after) }
    end
    manifest = {
      "patches" => {
        purl => {
          "uuid" => UUID,
          "exportedAt" => "Mon, 16 Nov 2026 00:00:00 GMT",
          "files" => entries,
          "vulnerabilities" => {
            GHSA => { "cves" => [], "summary" => "nokogiri end-to-end test",
                      "severity" => "HIGH", "description" => "nokogiri end-to-end test" }
          },
          "description" => "nokogiri end-to-end test",
          "license" => "MIT",
          "tier" => "free"
        }
      }
    }
    File.write(File.join(socket, "manifest.json"), JSON.pretty_generate(manifest) + "\n")
  end

  def installed(path)
    File.binread(File.join(@gem_dir, path))
  end

  def ruby_record
    before = installed("lib/nokogiri.rb")
    { "lib/nokogiri.rb" => [before, before + "\nmodule Nokogiri\n  #{RB_CONST} = 1\nend\n"] }
  end

  def c_record
    path = "ext/nokogiri/nokogiri.c"
    before = installed(path)
    anchor = /^[ \t]*mNokogiri[ \t]*=[ \t]*rb_define_module\("Nokogiri"\);[ \t]*\r?$/
    raise Failure, "#{path} has no `mNokogiri = rb_define_module(\"Nokogiri\");` line to patch after" unless before =~ anchor
    after = before.sub(anchor) { |line| "#{line}\n  rb_define_const(mNokogiri, \"#{C_CONST}\", INT2FIX(1));" }
    { path => [before, after] }
  end

  # The directory nokogiri's `extconf.rb` reads libxml2 patches from: the
  # one this release ships them in, else the one its build script names.
  def libxml2_patch_dir
    return "patches/libxml2" if File.directory?(File.join(@gem_dir, "patches"))
    return "ports/patches/libxml2" if File.directory?(File.join(@gem_dir, "ports", "patches"))
    # The JRuby gem ships neither, and may ship no build script: the record
    # is the one written for the ruby platform gem of a current release.
    return "patches/libxml2" if @java && !File.file?(File.join(@gem_dir, "ext/nokogiri/extconf.rb"))
    # A precompiled gem ships neither; its build script still says which.
    extconf = installed("ext/nokogiri/extconf.rb")
    return "ports/patches/libxml2" if extconf =~ /File\.join\(portsdir, *"patches"/
    return "patches/libxml2" if extconf =~ /File\.join\([A-Z_]+, *"patches"/
    nil
  end

  def libxml2_record
    dir = libxml2_patch_dir
    return nil unless dir
    { "#{dir}/#{LIBXML2_PATCH}" => [nil, LIBXML2_PATCH_BODY] }
  end

  # ---- the scenarios -----------------------------------------------------

  def scenario(name)
    puts "#{name}:"
    case name
    when "ruby" then applied(ruby_record, :native => false) { |now| now[RB_CONST] == 1 && now[C_CONST].nil? }
    when "c"
      # The JRuby gem ships the C source and compiles nothing: the file is
      # written, no build is made, and JRuby loads what it loaded before.
      if @java
        return applied(c_record, :native => false, :what => "JRuby loads no C constant, and the jars it loaded before") do |now|
          now[C_CONST].nil? && now[RB_CONST].nil? && now["jars"] == @baseline["jars"]
        end
      end
      native(c_record) { |now| now[C_CONST] == 1 }
    when "libxml2"
      record = libxml2_record
      return skip("this release reads no libxml2 patch directory") && nil unless record
      # The JRuby gem packs no libxml2: nothing of the record is in it.
      return not_in_build(record) if @java
      # Built against the system's libxml2: the build never opens the copy
      # the gem packs, so a patch to that copy is compiled into nothing.
      # Its file is written, the run fails and says so, and nothing
      # attests it.
      # (Where the filesystem records no reads the CLI cannot tell, and the
      # leg says so with --unread-check off.)
      if @shape == "system-libraries"
        return @opts[:unread_check] ? written_not_built(record) : skip("no read tracking here")
      end
      native(record) do |now|
        now["libxml_patches"].include?(LIBXML2_PATCH) &&
          (@baseline["libxml_patches"] - now["libxml_patches"]).empty?
      end
    else raise Failure, "unknown scenario #{name}"
    end
  end

  def skip(why)
    puts "  skip #{why}"
    true
  end

  def native(record, &effect)
    case @opts.fetch(:build)
    when "ok" then applied(record, :native => true, &effect)
    when "unavailable" then not_applied(record, "native_extension_build_failed")
    end
  end

  def events(stdout)
    JSON.parse(stdout).fetch("events", [])
  rescue JSON::ParserError
    []
  end

  def event(stdout)
    events(stdout).find { |e| e["purl"].to_s.start_with?("pkg:gem/nokogiri@#{@version}") }
  end

  def action(stdout)
    found = event(stdout)
    found ? found["action"] : nil
  end

  # The `vex` statuses for nokogiri: `["not_affected"]` when the patch is
  # attested, `[]` when it is left out.
  def vex_statuses
    out = File.join(@proj, "vex.json")
    FileUtils.rm_f(out)
    code, stdout, stderr, = sp("vex", "--product", PRODUCT, "--output", out)
    return [code, [], stdout + stderr] unless File.file?(out)
    doc = JSON.parse(File.read(out))
    statuses = (doc["statements"] || []).select { |s| s.to_s.include?("pkg:gem/nokogiri@#{@version}") }
                                        .map { |s| s["status"] }
    [code, statuses, stdout + stderr]
  end

  # The statement of the `vex` document the last `vex_statuses` wrote that
  # covers nokogiri, or `{}`.
  def vex_statement
    doc = JSON.parse(File.read(File.join(@proj, "vex.json")))
    (doc["statements"] || []).find { |s| s.to_s.include?("pkg:gem/nokogiri@#{@version}") } || {}
  rescue Errno::ENOENT, JSON::ParserError
    {}
  end

  def applied(record, native:, what: "Ruby loads the patched code", &effect)
    write_record(record)

    code, stdout, stderr, = sp("apply", "--check", "--json")
    check(code != 0, "`apply --check` reports the unapplied patch", "exit #{code}\n#{stdout}#{stderr}")

    code, stdout, stderr, secs = sp("apply", "--json")
    check(code.zero? && action(stdout) == "applied", "`apply` applies it (#{secs.round}s)",
          "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")

    # A JRuby gem is patched file by file: every file of the record it
    # takes is on disk as the patch wrote it.
    if @java
      record.each do |path, (_, after)|
        check(File.file?(File.join(@gem_dir, path)) && installed(path) == after, "#{path} is written")
      end
      check(leftovers.empty?, "nothing of a build was left in the gem home", leftovers.join("\n"))
    end

    now = probe
    check(effect.call(now), what, JSON.pretty_generate(now))
    check(now["smoke"] == @baseline["smoke"], "nokogiri still parses, queries, transforms and validates",
          "before #{@baseline['smoke'].inspect}\nafter  #{now['smoke'].inspect}")
    if @opts[:rails]
      check(now["rails_sanitize"] == @baseline["rails_sanitize"],
            "Rails #{now['rails']} boots on the patched nokogiri and sanitizes as before", now["rails_sanitize"].inspect)
    end
    if native
      check(now["binary_sha256"] != @baseline["binary_sha256"], "Ruby loads a rebuilt extension")
      check(now["libxml_loaded"] == @baseline["libxml_loaded"],
            "the rebuilt extension has the same libxml2 (#{now['libxml_loaded']})")
    else
      check(now["binary_sha256"] == @baseline["binary_sha256"], "no extension was rebuilt")
    end

    code, stdout, stderr, = sp("apply", "--check")
    check(code.zero?, "`apply --check` is in sync", "exit #{code}\n#{stdout}#{stderr}")

    code, stdout, stderr, secs = sp("apply", "--json")
    check(code.zero? && action(stdout) == "skipped", "a second `apply` has nothing to do (#{secs.round}s)",
          "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    again = probe
    check(again["binary_sha256"] == now["binary_sha256"], "and builds nothing")

    code, statuses, text = vex_statuses
    check(code.zero? && statuses == ["not_affected"], "`vex` attests the patch", "exit #{code} #{statuses.inspect}\n#{tail(text)}")

    rolled_back
  end

  def not_applied(record, reason)
    write_record(record)
    code, stdout, stderr, secs = sp("apply", "--json")
    check(code != 0 && (stdout + stderr).include?(reason),
          "`apply` fails with #{reason} (#{secs.round}s)", "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    diff = tree_diff(snapshot)
    check(diff.empty?, "nothing of the install was changed", diff.join("\n"))
    check(leftovers.empty?, "and nothing was left in the gem home", leftovers.join("\n"))
    check(probe == @baseline, "Ruby loads what it loaded before")

    code, stdout, stderr, = sp("apply", "--check")
    check(code != 0, "`apply --check` does not report it in sync", "exit #{code}\n#{stdout}#{stderr}")
    _, statuses, text = vex_statuses
    check(statuses.empty?, "`vex` does not attest it", "#{statuses.inspect}\n#{tail(text)}")

    code, stdout, stderr, = sp("rollback")
    check(code.zero?, "`rollback` of the unapplied record succeeds", "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
  end

  # A record with no file in this install's build of the gem (the JRuby
  # gem packs no libxml2, so a patch to it has nothing to change there):
  # `apply` succeeds without writing anything and says why, in the event of
  # the patch and, for a person, on stderr. The install counts as patched,
  # because the code the patch fixes is not in it: `apply --check` is in
  # sync and `vex` attests it.
  def not_in_build(record)
    write_record(record)

    code, stdout, stderr, secs = sp("apply", "--json")
    found = event(stdout) || {}
    check(code.zero? && found["action"] == "skipped" && found["errorCode"] == "not_in_platform_build",
          "`apply` succeeds and reports the patch as not part of this build (#{secs.round}s)",
          "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    check(found["reason"].to_s.include?("none of the patch's files are part of the JRuby build"),
          "and says so in plain words", found["reason"].inspect)
    check(warning_codes(stdout).empty?, "without a warning", warning_codes(stdout).inspect)
    code, stdout, stderr, = sp("apply")
    check(code.zero? && stderr.include?("none of the patch's files are part of the JRuby build"),
          "a person reads the same on stderr, and the run exits 0", "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")

    diff = tree_diff(snapshot)
    check(diff.empty?, "nothing of the install was changed", diff.join("\n"))
    check(leftovers.empty?, "and nothing was left in the gem home", leftovers.join("\n"))
    check(probe == @baseline, "Ruby loads what it loaded before")

    code, stdout, stderr, = sp("apply", "--check")
    check(code.zero?, "`apply --check` is in sync", "exit #{code}\n#{stdout}#{stderr}")
    code, statuses, text = vex_statuses
    check(code.zero? && statuses == ["not_affected"], "`vex` attests the patch", "exit #{code} #{statuses.inspect}\n#{tail(text)}")
    # Nothing was patched, and the statement does not say so: the code is
    # not in this build.
    statement = vex_statement
    check(statement["justification"] == "vulnerable_code_not_present" &&
          statement["impact_statement"].to_s.include?("is not in the installed build of the package") &&
          !statement["impact_statement"].to_s.include?("Patched via"),
          "as code that is not in this build, not as a patched package", statement.inspect)

    # `rollback` has nothing to restore, and says that.
    code, stdout, stderr, = sp("rollback", "--json", "--dry-run")
    found = event(stdout) || {}
    check(code.zero? && found["action"] == "skipped" && found["errorCode"] == "not_in_platform_build",
          "`rollback` reports that nothing of the patch was applied to this build",
          "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")

    rolled_back
  end

  def warning_codes(stdout)
    JSON.parse(stdout).fetch("warnings", []).map { |w| w["code"] }
  rescue JSON::ParserError
    []
  end

  # A record this install compiles nothing of. The patch is incomplete:
  # `apply` writes its files, which stay written, exits 1 and says that no
  # build holds them (a `failed` event with `native_extension_not_rebuilt`,
  # the warning of the same code, and an `Error:` line for a person). Ruby
  # loads the binary it loaded before, and neither `apply --check` nor
  # `vex` takes the install for patched. `rollback` takes the files out.
  def written_not_built(record)
    write_record(record)
    code, stdout, stderr, secs = sp("apply", "--json")
    found = event(stdout) || {}
    warned = warning_codes(stdout).include?("native_extension_not_rebuilt")
    check(code == 1 && found["action"] == "failed" && found["errorCode"] == "native_extension_not_rebuilt" && warned,
          "`apply` fails: the patch is incomplete, because nothing compiles it (#{secs.round}s)",
          "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    check(found["error"].to_s.include?("the patch's files were written"),
          "and says that its files were written", found["error"].inspect)
    record.each do |path, (_, after)|
      check(File.file?(File.join(@gem_dir, path)) && installed(path) == after, "#{path} is written")
    end
    check(leftovers.empty?, "nothing of a build was left in the gem home", leftovers.join("\n"))
    check(probe == @baseline, "Ruby loads what it loaded before")

    code, stdout, stderr, = sp("apply")
    check(code == 1 && stderr.include?("is incomplete: the patch's files were written"),
          "a person reads the same as an error, and the run exits 1", "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    record.each do |path, (_, after)|
      check(installed(path) == after, "#{path} stays written")
    end

    code, stdout, stderr, = sp("apply", "--check")
    check(code != 0, "`apply --check` does not report it in sync", "exit #{code}\n#{stdout}#{stderr}")
    _, statuses, text = vex_statuses
    check(statuses.empty?, "`vex` does not attest it", "#{statuses.inspect}\n#{tail(text)}")

    rolled_back
  end

  def rolled_back
    code, stdout, stderr, = sp("rollback")
    check(code.zero?, "`rollback` succeeds", "exit #{code}\n#{tail(stdout)}#{tail(stderr)}")
    diff = tree_diff(snapshot)
    check(diff.empty?, "every file of the install is as it was", diff.join("\n"))
    check(leftovers.empty?, "nothing of socket-patch is left in the gem home", leftovers.join("\n"))
    check(probe == @baseline, "Ruby loads what it loaded before the patch")
  end

  # Loads nokogiri and prints one `sp_probe` line of JSON: what was loaded
  # and whether it works. Old and new releases name things differently
  # (`libxml2_patches` before 1.11), and JRuby has no libxml2 at all: what
  # it loads is the gem's jars.
  PROBE = <<-'RUBY'
require "json"
require "digest"
require "nokogiri"
info = Nokogiri::VERSION_INFO
lx = info["libxml"] || {}
binary = $LOADED_FEATURES.grep(/nokogiri\.(bundle|so|dll)\z/).first
# The jars JRuby loaded (none on any other Ruby), each with its digest.
jars = {}
$LOADED_FEATURES.grep(/\.jar\z/).each do |jar|
  jars[File.basename(jar)] = File.file?(jar) ? Digest::SHA256.file(jar).hexdigest : nil
end
patches = lx["patches"] || lx["libxml2_patches"] || []
patches = patches.split(" ") if patches.is_a?(String)
doc = Nokogiri::XML("<r xmlns:n='urn:x'><a id='1'>one</a><n:b k='v'>two</n:b></r>")
node = doc.root.add_child("<c/>").first
node["x"] = "y"
node.content = "z"
html = Nokogiri::HTML("<html><body><p class='k'>hi</p></body></html>")
xslt = Nokogiri::XSLT("<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>" \
  "<xsl:template match='/'><out><xsl:value-of select='//a'/></out></xsl:template></xsl:stylesheet>")
xsd = Nokogiri::XML::Schema("<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'>" \
  "<xs:element name='q' type='xs:string'/></xs:schema>")
smoke = [
  doc.xpath("//a").first.text,
  doc.css("a").size,
  doc.at_xpath("//n:b", "n" => "urn:x")["k"],
  doc.at("c").to_xml,
  html.at_css("p.k").text,
  xslt.transform(doc).root.text,
  xsd.validate(Nokogiri::XML("<q>s</q>")).size
]
result = {
  "version" => Nokogiri::VERSION,
  "binary" => binary && File.basename(File.dirname(binary)) + "/" + File.basename(binary),
  "binary_sha256" => binary && Digest::SHA256.file(binary).hexdigest,
  "jars" => jars,
  "libxml_source" => lx["source"],
  "libxml_loaded" => lx["loaded"],
  "libxml_patches" => patches,
  "SOCKET_PATCH_E2E_RB" => Nokogiri.const_defined?(:SOCKET_PATCH_E2E_RB) ? Nokogiri::SOCKET_PATCH_E2E_RB : nil,
  "SOCKET_PATCH_E2E_C" => Nokogiri.const_defined?(:SOCKET_PATCH_E2E_C) ? Nokogiri::SOCKET_PATCH_E2E_C : nil,
  "smoke" => smoke
}
if ARGV.include?("--rails")
  # A Rails application, booted, sanitizing markup the way a view does:
  # ActionView hands it to rails-html-sanitizer, which parses with loofah
  # on this nokogiri. (`logger` first: Rails before 7.1 assumes it loaded.)
  require "logger"
  require "rails"
  require "action_controller/railtie"
  class SocketPatchE2E < Rails::Application
    config.eager_load = false
    config.secret_key_base = "socket-patch-nokogiri-e2e-" * 4
    config.logger = Logger.new(nil)
  end
  SocketPatchE2E.initialize!
  result["rails"] = Rails.version
  result["rails_sanitize"] = ActionController::Base.helpers.sanitize("<p onclick='x()'>ok<script>bad()</script></p>")
end
puts "sp_probe\t" + JSON.generate(result)
  RUBY
end

opts = { :install => "any", :build => "ok", :gem_home => "project", :scenarios => %w[ruby c libxml2], :gems => [],
         :settings => [], :unread_check => true }
parser = OptionParser.new do |o|
  o.banner = "usage: ruby nokogiri_e2e.rb --socket-patch BIN --nokogiri VERSION [options]"
  o.on("--socket-patch BIN", "the socket-patch binary under test") { |v| opts[:socket_patch] = v }
  o.on("--nokogiri VERSION", "the nokogiri release to install") { |v| opts[:nokogiri] = v }
  o.on("--install SHAPE", %w[any precompiled source system-libraries java],
       "the install to make and require: precompiled (Bundler's default where a platform gem exists),",
       "source (the ruby platform gem, compiled here), system-libraries (compiled against the system's",
       "libxml2), java, or any (default)") { |v| opts[:install] = v }
  o.on("--[no-]unread-check", "whether this filesystem records file reads (default: yes), which is what tells",
       "socket-patch that a system-libraries build read nothing of a libxml2 patch") { |v| opts[:unread_check] = v }
  o.on("--build RESULT", %w[ok unavailable],
       "what a patch that needs a rebuild must do: ok (default), unavailable (no toolchain: fail,",
       "change nothing). A JRuby install builds nothing either way") { |v| opts[:build] = v }
  o.on("--hide-toolchain", "run socket-patch with no compiler or make on PATH (with --build unavailable)") do
    opts[:hide_toolchain] = true
  end
  o.on("--gem-home WHERE", %w[project ambient],
       "where Bundler installs: project (default: `vendor/bundle`, by the project's own Bundler",
       "config) or ambient (wherever this environment's Bundler and RubyGems settings say, which",
       "in an official Ruby image is /usr/local/bundle; only for a throwaway environment)") { |v| opts[:gem_home] = v }
  o.on("--scenarios LIST", Array, "of ruby,c,libxml2 (default: all three)") { |v| opts[:scenarios] = v }
  o.on("--rails VERSION", "also install this Rails (a Gemfile requirement, for example '~> 7.1.0') and check",
       "that a booted application sanitizes HTML through the patched nokogiri") { |v| opts[:rails] = v }
  o.on("--bundle-setting KEY=VALUE", "one more Bundler setting for the install, for example",
       "BUNDLE_BUILD__NOKOGIRI=--use-system-libraries") { |v| opts[:settings] << v }
  o.on("--gem LINE", "one more Gemfile line, for example 'gem \"rails\", \"7.1.5\"'") { |v| opts[:gems] << v }
  o.on("--work DIR", "build the project in DIR and keep it") { |v| opts[:work] = v }
end
parser.parse!
opts[:socket_patch] ||= ENV["SOCKET_PATCH_BIN"]
abort(parser.help) unless opts[:socket_patch] && opts[:nokogiri]

begin
  NokogiriE2E.new(opts).run
rescue Failure => e
  warn e.message
  exit 1
end
