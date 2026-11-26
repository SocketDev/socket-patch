# frozen_string_literal: true

# A stand-in for Socket's patch service, for the hosted and vendored
# scenarios of nokogiri_e2e.rb: the patches API, the gem patch's registry
# (a RubyGems compact index) and the artifact downloads, on a loopback port,
# and on a second port a stand-in for the upstream registry's file host.
#
# What it serves is real: the ruby-platform nokogiri gem and every platform
# gem the project's lock names, downloaded from rubygems.org and repacked
# with one Ruby file changed. That is what the service's own repack makes of
# a Ruby-only patch, and it needs no compiler, so a leg can run it anywhere.
# A patch to C sources is delivered the same way (a platform gem whose
# binaries were rebuilt on the service's side), so the client paths under
# test are the same.
#
# It answers the way the patch service does:
#
#   * The gem's fix is one patch (`uuid`), the ruby gem's. Each patched
#     platform gem has a patch of its own (`uuid_of(platform)`): the search
#     routes return its record beside the gem's, and its reference serves
#     that gem (`tarball`) and its stub gemspec (`gem-stub-gemspec`). One
#     reference request answers for every uuid it names.
#   * A reference request that carries `"gemBuilds": true` gets the gem
#     patch's registry under a snapshot URL (`…/<uuid>/s/<key>`, the key
#     derived from what the registry lists) and the list of the version's
#     gems (`gemBuilds`): the ruby gem under the gem's patch, each patched
#     platform gem under its own, and each pass-through platform with
#     `"patchUuid": null`. A request without it gets the plain URL and no
#     list.
#   * The registry under a snapshot lists every gem of that list. A
#     pass-through platform is upstream's own line, and its file is relayed:
#     a 200 with upstream's own bytes. With `:redirect => true` it is a 302
#     to the upstream stand-in (`upstream_url`), which serves the real gem:
#     an answer a client must follow too.
#     A platform whose patched build is still being made is in neither the
#     list nor the registry. A snapshot answers as it did after `publish`
#     made a newer one.
#
#   service = PatchService.new("nokogiri", "1.18.10", %w[arm64-darwin x86_64-linux-gnu],
#                              uuid, ghsa, dir, mark, :pass_through => %w[arm64-darwin])
#   service.index_url                # what a hosted lock names as the gem's remote
#   service.publish("arm64-darwin")  # its patched build is there: a newer snapshot
#
# Options: `:pass_through` (platforms served as upstream's own gem),
# `:redirect => true` (their files are redirected to the upstream stand-in
# and not relayed), `:building` (platforms left out of the list),
# `:list => false` (a patch of the ruby gem alone: no list for any request).
#
# No gem dependencies, and nothing newer than Ruby 2.1 syntax: the file is
# loaded on every leg, though its scenarios only run where nokogiri has
# platform gems (Ruby 2.5 and later).

require "digest"
require "fileutils"
require "json"
require "rubygems/package"
require "socket"
require "stringio"
require "tmpdir"
require "yaml"
require "zlib"

class PatchService
  ORG = "nokogiri-e2e"
  TOKEN = "e2e-grant-token"

  Built = Struct.new(:file, :token, :platform, :bytes, :sha256, :sri, :stub, :deps, :ruby, :rubygems)

  attr_reader :uuid, :ghsa

  # `platforms`: the platform tokens the lock names (`x86_64-linux-gnu`, …).
  # `mark`: the Ruby text appended to `lib/<name>.rb` of every patched gem.
  def initialize(name, version, platforms, uuid, ghsa, work, mark, options = {})
    @name = name
    @version = version
    @uuid = uuid
    @ghsa = ghsa
    @work = work
    @mark = mark
    @list = options.fetch(:list, true)
    @redirect = options.fetch(:redirect, false)
    @requests = []
    @upstream_requests = []
    @reference_requests = []
    @lock = Mutex.new
    @patch_routes_up = true
    FileUtils.mkdir_p(@work)
    pass_through = options.fetch(:pass_through, [])
    building = options.fetch(:building, [])
    @states = {}
    @upstream = {}
    @patched = {}
    ([nil] + platforms.sort).each do |platform|
      @upstream[platform], @patched[platform] = repack(platform)
      next unless platform
      @states[platform] = if building.include?(platform) then :building
                          elsif pass_through.include?(platform) then :pass_through
                          else :patched
                          end
    end
    @snapshots = {}
    @server = TCPServer.new("127.0.0.1", 0)
    @files = TCPServer.new("127.0.0.1", 0)
    @threads = [[@server, :respond], [@files, :respond_upstream]].map do |server, route|
      Thread.new { loop { serve(server.accept, route) } }
    end
  end

  def url
    "http://127.0.0.1:#{@server.addr[1]}"
  end

  # The stand-in for the upstream registry's file host: `gems/<file>` of
  # every gem of the version, as upstream published it.
  def upstream_url
    "http://127.0.0.1:#{@files.addr[1]}"
  end

  # The gem patch's registry as a lock names it after a hosted scan: the
  # snapshot of what the registry lists now, closed by a slash.
  def index_url
    key, = @lock.synchronize { snapshot }
    key ? "#{url}#{registry_path}/s/#{key}/" : "#{url}#{registry_path}/"
  end

  def stop
    @threads.each(&:kill)
    @server.close
    @files.close
  end

  # From now on the registry and the downloads answer 503: what a machine
  # without access to the patch service sees.
  def take_down
    @lock.synchronize { @patch_routes_up = false }
  end

  def bring_up
    @lock.synchronize { @patch_routes_up = true }
  end

  # The patched build of `platform` is there: the list names its patch from
  # now on, under a newer snapshot. Returns that snapshot's `index_url`.
  def publish(platform)
    @lock.synchronize do
      raise ArgumentError, "#{platform} is not a platform of this service" unless @states.key?(platform)
      @states[platform] = :patched
    end
    index_url
  end

  # [verb, path, status] of every request so far.
  def requests
    @lock.synchronize { @requests.dup }
  end

  # The same for the upstream stand-in.
  def upstream_requests
    @lock.synchronize { @upstream_requests.dup }
  end

  # The body of every package reference request so far, parsed.
  def reference_requests
    @lock.synchronize { @reference_requests.dup }
  end

  def forget_requests
    @lock.synchronize { [@requests, @upstream_requests, @reference_requests].each(&:clear) }
  end

  # The sha256 the registry lists for `platform` now: its patched build's,
  # or upstream's own gem's for a pass-through platform.
  def sha256_of(platform)
    @lock.synchronize { (@states[platform] == :patched ? @patched : @upstream).fetch(platform).sha256 }
  end

  # The patch of `platform`'s patched build, or nil while it has none.
  def uuid_of(platform)
    @lock.synchronize { @states[platform] == :patched ? build_uuid(platform) : nil }
  end

  private

  # ---- the gems ------------------------------------------------------------

  def fetch(file)
    path = File.join(@work, "upstream-#{file}")
    return path if File.file?(path)
    require "open-uri"
    tries = 0
    begin
      tries += 1
      URI.open("https://rubygems.org/gems/#{file}", "rb") { |io| File.binwrite(path, io.read) }
    rescue StandardError
      FileUtils.rm_f(path)
      raise if tries >= 3
      sleep 2
      retry
    end
    path
  end

  # The upstream gem of `platform` (nil: the ruby gem) as it is, and with
  # the mark appended to `lib/<name>.rb`, each with the facts the index and
  # the API state about it.
  #
  # A `.gem` is a tar of `metadata.gz` (the gemspec), `data.tar.gz` (the
  # files) and `checksums.yaml.gz`. Like the service's own repack, this one
  # keeps `metadata.gz` byte for byte and rewrites the other two: the
  # gemspec of an installed copy is written from that member, and a patched
  # gem that replaces the copy's files must carry the same one.
  def repack(platform)
    file = platform ? "#{@name}-#{@version}-#{platform}.gem" : "#{@name}-#{@version}.gem"
    upstream = fetch(file)
    spec = Gem::Package.new(upstream).spec
    members = {}
    File.open(upstream, "rb") do |io|
      Gem::Package::TarReader.new(io) { |tar| tar.each { |entry| members[entry.full_name] = entry.read } }
    end
    metadata_gz = members.fetch("metadata.gz")
    data_gz = patched_data(members.fetch("data.tar.gz"), platform.nil?)
    sums = { "metadata.gz" => metadata_gz, "data.tar.gz" => data_gz }
    checksums = {
      "SHA256" => Hash[sums.map { |name, bytes| [name, Digest::SHA256.hexdigest(bytes)] }],
      "SHA512" => Hash[sums.map { |name, bytes| [name, Digest::SHA512.hexdigest(bytes)] }]
    }
    out = StringIO.new("".b)
    Gem::Package::TarWriter.new(out) do |tar|
      [["metadata.gz", metadata_gz], ["data.tar.gz", data_gz],
       ["checksums.yaml.gz", gzip(YAML.dump(checksums))]].each do |name, bytes|
        tar.add_file_simple(name, 0o444, bytes.bytesize) { |io| io.write(bytes) }
      end
    end
    deps = spec.runtime_dependencies.map { |d| "#{d.name}:#{d.requirement.as_list.join('&')}" }.sort.join(",")
    [File.binread(upstream), out.string].map do |bytes|
      Built.new(file, platform ? "#{@version}-#{platform}" : @version, platform, bytes,
                Digest::SHA256.hexdigest(bytes), sri(bytes), spec.to_ruby, deps,
                spec.required_ruby_version.as_list.join("&"),
                spec.required_rubygems_version.as_list.join("&"))
    end
  end

  def gzip(bytes)
    out = StringIO.new("".b)
    gz = Zlib::GzipWriter.new(out)
    gz.mtime = 1
    gz.write(bytes)
    gz.close
    out.string
  end

  # `data.tar.gz` with the mark appended to `lib/<name>.rb`, every other
  # entry as it was. `record`: remember that file's two contents, for the
  # patch record the API serves.
  def patched_data(data_gz, record)
    target = "lib/#{@name}.rb"
    out = StringIO.new("".b)
    Gem::Package::TarWriter.new(out) do |tar|
      Zlib::GzipReader.wrap(StringIO.new(data_gz)) do |plain|
        Gem::Package::TarReader.new(plain) do |entries|
          entries.each do |entry|
            mode = entry.header.mode
            if entry.directory?
              tar.mkdir(entry.full_name, mode)
            elsif entry.header.typeflag == "2"
              tar.add_symlink(entry.full_name, entry.header.linkname, mode)
            elsif entry.file?
              bytes = entry.read || "".b
              if entry.full_name == target
                @before, @after = bytes, bytes + @mark if record
                bytes += @mark
              end
              tar.add_file_simple(entry.full_name, mode, bytes.bytesize) { |io| io.write(bytes) }
            end
          end
        end
      end
    end
    gzip(out.string)
  end

  def git_sha256(bytes)
    Digest::SHA256.hexdigest("blob #{bytes.bytesize}\0".b + bytes.b)
  end

  def sri(bytes)
    "sha512-" + [Digest::SHA512.digest(bytes)].pack("m0")
  end

  # ---- what the service has ------------------------------------------------
  #
  # Everything below reads `@states` and `@snapshots`, and runs with `@lock`
  # held.

  # The uuid of the patch of `platform`'s patched build (nil: the gem's).
  def build_uuid(platform)
    return @uuid unless platform
    hex = Digest::SHA256.hexdigest("#{@uuid}/#{platform}")
    [hex[0, 8], hex[8, 4], "4" + hex[13, 3], "8" + hex[17, 3], hex[20, 12]].join("-")
  end

  # The platforms with a patched build.
  def patched_platforms
    @states.select { |_, state| state == :patched }.keys
  end

  # What the registry lists now, as [state, gem] rows: the patched ruby gem,
  # then each platform gem that is patched or passed through.
  def listing
    rows = [[:patched, @patched[nil]]]
    @states.each do |platform, state|
      rows << [state, (state == :patched ? @patched : @upstream).fetch(platform)] unless state == :building
    end
    rows
  end

  # [key, rows] of the snapshot of `listing`, which answers under that key
  # from now on; nil for a service with no list.
  def snapshot
    return nil unless @list
    rows = listing
    text = rows.map { |state, gem| [gem.token, gem.sha256, state].join(" ") }.join("\n")
    key = Digest::SHA256.hexdigest(text)[0, 12]
    @snapshots[key] ||= rows
    [key, rows]
  end

  # ---- the routes ----------------------------------------------------------

  def registry_path
    "/patch-registry/gem/#{TOKEN}/#{@uuid}"
  end

  def info_body(rows)
    lines = rows.map do |_, g|
      "#{g.token} #{g.deps}|checksum:#{g.sha256},ruby:#{g.ruby},rubygems:#{g.rubygems}\n"
    end
    "---\n" + lines.join
  end

  def base_purl
    "pkg:gem/#{@name}@#{@version}"
  end

  # The purl of the patch of `platform`'s gem (nil: the gem's own patch).
  def patch_purl(platform = nil)
    "#{base_purl}?platform=#{platform || 'ruby'}"
  end

  def vulnerabilities
    { @ghsa => { "cves" => [], "summary" => "nokogiri end-to-end test", "severity" => "high",
                 "description" => "nokogiri end-to-end test" } }
  end

  def artifact_url(platform, leaf)
    "#{url}/artifacts/#{build_uuid(platform)}/#{leaf}"
  end

  # The gem and the stub gemspec of the patch of `platform`'s gem.
  def artifacts(platform)
    gem = @patched.fetch(platform)
    [{ "kind" => "tarball", "url" => artifact_url(platform, gem.file),
       "contentType" => "application/octet-stream", "sizeBytes" => gem.bytes.bytesize,
       "integrity" => { "sha512" => gem.sri, "sha256" => gem.sha256 } },
     { "kind" => "gem-stub-gemspec", "url" => artifact_url(platform, gem.file.sub(/\.gem\z/, ".gemspec")),
       "contentType" => "text/plain", "sizeBytes" => gem.stub.bytesize,
       "integrity" => { "sha512" => sri(gem.stub) } }]
  end

  # The reference of the patch `uuid`, or nil for a uuid that is no patch
  # here. `with_list`: the request asked for the list of the gem's builds.
  def package_result(uuid, with_list)
    platform = patched_platforms.find { |p| build_uuid(p) == uuid }
    if platform
      return { "status" => "granted", "url" => artifact_url(platform, @patched.fetch(platform).file),
               "purl" => patch_purl(platform), "artifacts" => artifacts(platform) }
    end
    return nil unless uuid == @uuid
    ruby_gem = @patched[nil]
    identifiers = { "name" => @name, "version" => @version, "gemChecksumSha256" => ruby_gem.sha256 }
    index = "#{url}#{registry_path}/"
    key, rows = with_list ? snapshot : nil
    if key
      index += "s/#{key}"
      builds = rows.map do |state, gem|
        { "platform" => gem.platform || "ruby", "gemChecksumSha256" => gem.sha256,
          "patchUuid" => state == :patched ? build_uuid(gem.platform) : nil }
      end
      identifiers["gemBuilds"] = builds.sort_by { |build| build["platform"] }
    end
    {
      "status" => "granted",
      "url" => "#{url}/patch/gem/#{@name}/#{@version}/#{TOKEN}/#{@uuid}/#{ruby_gem.file}",
      "purl" => patch_purl,
      "artifacts" => artifacts(nil),
      "registryOverride" => { "kind" => "rubygems-compact-index", "indexUrl" => index, "identifiers" => identifiers }
    }
  end

  # The patches a search finds for the gem: the gem's own, and the patch of
  # each patched platform gem, published after it.
  def found_patches
    [nil] + patched_platforms
  end

  def json(body)
    [200, "application/json", JSON.generate(body)]
  end

  # status, content type, body and extra headers of the answer to `verb
  # path` on the service's port.
  def respond(verb, path, body)
    @lock.synchronize { route(verb, path, body) }
  end

  def route(verb, path, body)
    api = "/v0/orgs/#{ORG}/patches"
    if verb == "POST" && path == "#{api}/batch"
      patches = found_patches.map do |platform|
        { "uuid" => build_uuid(platform), "purl" => patch_purl(platform), "tier" => "free", "cveIds" => [],
          "ghsaIds" => [@ghsa], "severity" => "high", "title" => "nokogiri end-to-end test" }
      end
      return json("packages" => [{ "purl" => base_purl, "patches" => patches }], "canAccessPaidPatches" => false)
    elsif path.start_with?("#{api}/by-package/")
      patches = found_patches.reverse.map do |platform|
        { "uuid" => build_uuid(platform), "purl" => patch_purl(platform),
          "publishedAt" => platform ? "2026-03-01T00:00:00Z" : "2026-02-01T00:00:00Z",
          "description" => "nokogiri end-to-end test", "license" => "MIT", "tier" => "free",
          "vulnerabilities" => vulnerabilities }
      end
      return json("patches" => patches, "canAccessPaidPatches" => false)
    elsif path.start_with?("#{api}/view/")
      platform = found_patches.find { |p| build_uuid(p) == File.basename(path) }
      return [404, "text/plain", ""] unless platform || File.basename(path) == @uuid
      return json("uuid" => build_uuid(platform), "purl" => patch_purl(platform),
                  "publishedAt" => "2026-02-01T00:00:00Z",
                  "files" => { "lib/#{@name}.rb" => { "beforeHash" => git_sha256(@before),
                                                      "afterHash" => git_sha256(@after) } },
                  "vulnerabilities" => vulnerabilities, "description" => "nokogiri end-to-end test",
                  "license" => "MIT", "tier" => "free")
    elsif verb == "POST" && path == "#{api}/package"
      asked = begin
        JSON.parse(body.to_s)
      rescue JSON::ParserError
        {}
      end
      @reference_requests << asked
      results = {}
      Array(asked["uuids"]).each do |uuid|
        result = package_result(uuid, asked["gemBuilds"] == true)
        results[uuid] = result if result
      end
      return json("results" => results)
    end

    serves_patch = path.start_with?(registry_path + "/") || path.start_with?("/artifacts/") ||
                   path.start_with?("/patch/")
    return [404, "text/plain", ""] unless serves_patch
    return [503, "text/plain", ""] unless @patch_routes_up
    return download(File.basename(path)) unless path.start_with?(registry_path + "/")

    # The registry: under a snapshot, the gems that snapshot lists; under
    # the plain URL, the patched ruby gem alone.
    rest = path[(registry_path.size + 1)..-1]
    rows = [[:patched, @patched[nil]]]
    if rest =~ %r{\As/([0-9a-f]+)/(.*)\z}
      rows = @snapshots[Regexp.last_match(1)]
      rest = Regexp.last_match(2)
      return [404, "text/plain", ""] unless rows
    end
    index = { "Cache-Control" => "public, no-cache" }
    info = info_body(rows)
    case rest
    when "versions"
      tokens = rows.map { |_, g| g.token }.join(",")
      [200, "text/plain",
       "created_at: 2026-01-01T00:00:00Z\n---\n#{@name} #{tokens} #{Digest::MD5.hexdigest(info)}\n", index]
    when "info/#{@name}" then [200, "text/plain", info, index]
    when "names" then [200, "text/plain", "---\n#{@name}\n", index]
    else
      # The row of a pass-through platform holds upstream's own gem.
      state, gem = rows.find { |_, g| "gems/#{g.file}" == rest }
      if state == :pass_through && @redirect
        [302, "text/plain", "", { "Location" => "#{upstream_url}/gems/#{gem.file}", "Cache-Control" => "no-store" }]
      elsif gem then [200, "application/octet-stream", gem.bytes]
      else [404, "text/plain", ""]
      end
    end
  end

  # An artifact of a patch, by its file name: a patched gem or its stub.
  def download(leaf)
    gems = @patched.values
    gem = gems.find { |g| g.file == leaf }
    stub = gems.find { |g| g.file.sub(/\.gem\z/, ".gemspec") == leaf }
    if gem then [200, "application/octet-stream", gem.bytes]
    elsif stub then [200, "text/plain", stub.stub]
    else [404, "text/plain", ""]
    end
  end

  # The answer of the upstream stand-in: upstream's own gem files.
  def respond_upstream(_verb, path, _body)
    gem = @upstream.values.find { |g| "/gems/#{g.file}" == path }
    gem ? [200, "application/octet-stream", gem.bytes] : [404, "text/plain", ""]
  end

  REASONS = { 200 => "OK", 302 => "Found", 404 => "Not Found", 503 => "Service Unavailable" }.freeze

  def serve(socket, route)
    line = socket.gets
    return unless line
    verb, target, = line.split(" ")
    length = 0
    while (header = socket.gets) && header != "\r\n"
      key, value = header.split(":", 2)
      length = value.to_i if key.casecmp("content-length").zero?
    end
    sent = length > 0 ? socket.read(length) : nil
    path = target.to_s.split("?").first
    status, type, body, headers = send(route, verb, path, sent)
    log = route == :respond ? @requests : @upstream_requests
    @lock.synchronize { log << [verb, path, status] }
    extra = (headers || {}).map { |name, value| "#{name}: #{value}\r\n" }.join
    socket.write("HTTP/1.1 #{status} #{REASONS.fetch(status)}\r\nContent-Type: #{type}\r\n" \
                 "Content-Length: #{body.bytesize}\r\nETag: \"#{Digest::MD5.hexdigest(body)}\"\r\n" \
                 "#{extra}Connection: close\r\n\r\n")
    socket.write(body) unless verb == "HEAD"
  rescue StandardError
    nil
  ensure
    socket.close
  end
end
