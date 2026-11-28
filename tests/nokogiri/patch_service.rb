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
#     platform gem has a patch of its own (`uuid_of(platform)`), which no
#     search returns: a client learns of it from the gem's list
#     (`gemBuilds`) and reads its record by uuid (`view`). Its reference
#     serves that gem (`tarball`) and its stub gemspec
#     (`gem-stub-gemspec`), both named after the gem and its version
#     alone, as every patch's artifacts are; the ruby gem's reference has
#     no stub. One reference request answers for every uuid it names, a
#     reference names its package without a platform, and each patch has a
#     grant token of its own.
#   * Every patch stamps the files it changes with a header that names
#     that patch. The same change is therefore other bytes in each gem,
#     and the record of a platform gem's patch lists that gem's own
#     hashes: a copy of a platform gem never matches the gem patch's.
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
#     A platform upstream does not publish (`:unlisted`) is in neither the
#     list nor the registry. A snapshot answers as it did after `publish`
#     made a newer one.
#   * While a patched build is being built again (`rebuild`), the registry
#     as it stands lists upstream's own gem for that platform: that is
#     what a `gemBuilds` request with no key is answered, under another
#     snapshot. A request that presents the key of a snapshot it holds
#     (`"gemSnapshotKeys": { "<uuid>": "<key>" }`) is answered that
#     snapshot, as it was, while every patched gem it lists still is one
#     and one of them is being rebuilt. Under every snapshot the gem being
#     rebuilt is a 404 until `rebuilt`. Without `gemBuilds` the key is
#     ignored.
#
#   service = PatchService.new("nokogiri", "1.18.10", %w[arm64-darwin x86_64-linux-gnu],
#                              uuid, ghsa, dir, mark, :pass_through => %w[arm64-darwin])
#   service.index_url                # what a hosted lock names as the gem's remote
#   service.publish("arm64-darwin")  # its patched build is there: a newer snapshot
#
# Options: `:pass_through` (platforms served as upstream's own gem),
# `:redirect => true` (their files are redirected to the upstream stand-in
# and not relayed), `:unlisted` (platforms left out of the list),
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
    unlisted = options.fetch(:unlisted, [])
    @rebuilding = []
    @states = {}
    @upstream = {}
    @patched = {}
    @contents = {}
    ([nil] + platforms.sort).each do |platform|
      @upstream[platform], @patched[platform] = repack(platform)
      next unless platform
      @states[platform] = if unlisted.include?(platform) then :unlisted
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

  # The patched build of `platform` is being built again: its gem is not
  # served, and the registry as it stands lists upstream's gem for it.
  def rebuild(platform)
    @lock.synchronize { @rebuilding |= [platform] }
  end

  # That build is back, with the bytes it had.
  def rebuilt(platform)
    @lock.synchronize { @rebuilding.delete(platform) }
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
    data_gz = patched_data(members.fetch("data.tar.gz"), platform)
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

  # `data.tar.gz` with `lib/<name>.rb` stamped as the patch of `platform`'s
  # gem and the mark appended to it, every other entry as it was. That
  # file's two contents are kept for the record the API serves of that
  # patch.
  def patched_data(data_gz, platform)
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
                patched = stamp(bytes, platform) + @mark
                @contents[platform] = [bytes, patched]
                bytes = patched
              end
              tar.add_file_simple(entry.full_name, mode, bytes.bytesize) { |io| io.write(bytes) }
            end
          end
        end
      end
    end
    gzip(out.string)
  end

  # `bytes` with the header the service puts in a file a patch changes,
  # under the file's leading magic comments. It names the patch (here the
  # one of `platform`'s gem) and the day it was published.
  def stamp(bytes, platform)
    lines = bytes.lines
    lead = lines.take_while { |line| line =~ /\A#(!|\s*(en)?coding\b|\s*frozen_string_literal\b)/ }
    day = platform ? "Sun, 01 Mar 2026 00:00:00 GMT" : "Sun, 01 Feb 2026 00:00:00 GMT"
    header = "# Socket Community Patch: https://socket.dev\n# Date: #{day}\n" \
             "# For more information see https://socket.dev/patch/#{build_uuid(platform)}\n"
    lead.join + header.b + lines.drop(lead.size).join
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
    uuid_from("#{@uuid}/#{platform}")
  end

  # The grant token of that patch: each patch has its own.
  def token_of(platform)
    uuid_from("grant/#{build_uuid(platform)}")
  end

  def uuid_from(seed)
    hex = Digest::SHA256.hexdigest(seed)
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
      next if state == :unlisted
      # A build that is being rebuilt is not there to list.
      state = :pass_through if @rebuilding.include?(platform)
      rows << [state, (state == :patched ? @patched : @upstream).fetch(platform)]
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
    "/patch-registry/gem/#{token_of(nil)}/#{@uuid}"
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

  # Where the patch of `platform`'s gem serves its gem (`gem`) or its stub
  # gemspec (`gemspec`): under that patch's own token and uuid, in a file
  # named after the gem and its version alone, whatever the platform.
  def artifact_path(platform, extension)
    "/patch/gem/#{@name}/#{@version}/#{token_of(platform)}/#{build_uuid(platform)}/#{@name}-#{@version}.#{extension}"
  end

  # The artifacts of the patch of `platform`'s gem: the gem, and for a
  # platform gem its stub gemspec. The ruby gem builds an extension on
  # install, so it has no stub.
  def artifacts(platform)
    gem = @patched.fetch(platform)
    tarball = { "kind" => "tarball", "url" => url + artifact_path(platform, "gem"),
                "contentType" => "application/octet-stream", "sizeBytes" => gem.bytes.bytesize,
                "integrity" => { "sha512" => gem.sri, "sha256" => gem.sha256 } }
    return [tarball] unless platform
    [tarball,
     { "kind" => "gem-stub-gemspec", "url" => url + artifact_path(platform, "gemspec"),
       "contentType" => "text/plain", "sizeBytes" => gem.stub.bytesize,
       "integrity" => { "sha512" => sri(gem.stub), "sha256" => nil } }]
  end

  # The reference of the patch `uuid`, or nil for a uuid that is no patch
  # here. `with_list`: the request asked for the list of the gem's builds;
  # `held`: the key of the snapshot the request presents for the patch.
  def package_result(uuid, with_list, held = nil)
    platform = patched_platforms.find { |p| build_uuid(p) == uuid }
    if platform
      # A platform gem's patch has a registry of its own, which no client
      # of the gem's list needs and this stand-in does not serve.
      own = { "name" => @name, "version" => @version, "gemChecksumSha256" => @patched.fetch(platform).sha256 }
      return { "status" => "granted", "url" => url + artifact_path(platform, "gem"),
               "purl" => base_purl, "artifacts" => artifacts(platform),
               "registryOverride" => { "kind" => "rubygems-compact-index",
                                       "indexUrl" => "#{url}/patch-registry/gem/#{token_of(platform)}/#{uuid}/",
                                       "identifiers" => own },
               "rebuiltFromUuid" => @uuid }
    end
    return nil unless uuid == @uuid
    ruby_gem = @patched[nil]
    identifiers = { "name" => @name, "version" => @version, "gemChecksumSha256" => ruby_gem.sha256 }
    index = "#{url}#{registry_path}/"
    key, rows = with_list ? snapshot : nil
    # The snapshot the client holds, while it stands and a gem of it is
    # being rebuilt: every patched gem it lists is still a patched one.
    kept = key && @snapshots[held]
    if kept
      patched = kept.select { |state, gem| state == :patched && gem.platform }.map { |_, gem| gem.platform }
      stands = patched.all? { |platform| @states[platform] == :patched }
      key, rows = held, kept if stands && patched.any? { |platform| @rebuilding.include?(platform) }
    end
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
      "url" => url + artifact_path(nil, "gem"),
      "purl" => base_purl,
      "artifacts" => artifacts(nil),
      "registryOverride" => { "kind" => "rubygems-compact-index", "indexUrl" => index, "identifiers" => identifiers },
      "rebuiltFromUuid" => nil
    }
  end

  # The patches a search finds for the gem: the gem's own. The patch of a
  # platform gem is left out of every search.
  def found_patches
    [nil]
  end

  # The gems that have a patch to view (nil: the ruby gem).
  def viewable
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
      viewed = viewable.select { |p| build_uuid(p) == File.basename(path) }
      return [404, "text/plain", ""] if viewed.empty?
      platform = viewed.first
      before, after = @contents.fetch(platform)
      return json("uuid" => build_uuid(platform), "purl" => patch_purl(platform),
                  "publishedAt" => platform ? "2026-03-01T00:00:00Z" : "2026-02-01T00:00:00Z",
                  "files" => { "lib/#{@name}.rb" => { "beforeHash" => git_sha256(before),
                                                      "afterHash" => git_sha256(after) } },
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
        held = asked["gemSnapshotKeys"]
        result = package_result(uuid, asked["gemBuilds"] == true, held.is_a?(Hash) ? held[uuid] : nil)
        results[uuid] = result if result
      end
      return json("results" => results)
    end

    serves_patch = path.start_with?(registry_path + "/") || path.start_with?("/patch/")
    return [404, "text/plain", ""] unless serves_patch
    return [503, "text/plain", ""] unless @patch_routes_up
    return download(path) unless path.start_with?(registry_path + "/")

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
      if state == :patched && gem && @rebuilding.include?(gem.platform) then [404, "text/plain", ""]
      elsif state == :pass_through && @redirect
        [302, "text/plain", "", { "Location" => "#{upstream_url}/gems/#{gem.file}", "Cache-Control" => "no-store" }]
      elsif gem then [200, "application/octet-stream", gem.bytes]
      else [404, "text/plain", ""]
      end
    end
  end

  # An artifact of a patch, by its path: the patch's gem, or the stub
  # gemspec of a platform gem's patch.
  def download(path)
    platform = viewable.find { |p| path == artifact_path(p, "gem") }
    return [200, "application/octet-stream", @patched.fetch(platform).bytes] if platform || path == artifact_path(nil, "gem")
    stubbed = patched_platforms.find { |p| path == artifact_path(p, "gemspec") }
    stubbed ? [200, "text/plain", @patched.fetch(stubbed).stub] : [404, "text/plain", ""]
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
