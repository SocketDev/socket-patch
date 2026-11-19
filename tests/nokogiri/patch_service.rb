# frozen_string_literal: true

# A stand-in for Socket's patch service, for the hosted and vendored
# scenarios of nokogiri_e2e.rb: the patches API, the per-patch gem registry
# (a RubyGems compact index) and the artifact downloads, on a loopback port.
#
# What it serves is real: the ruby-platform nokogiri gem and every platform
# gem the project's lock names, downloaded from rubygems.org and repacked
# with one Ruby file changed. That is what the service's own repack makes of
# a Ruby-only patch, and it needs no compiler, so a leg can run it anywhere.
# A patch to C sources is delivered the same way (a platform gem whose
# binaries were rebuilt on the service's side), so the client paths under
# test are the same.
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
  # `mark`: the Ruby text appended to `lib/<name>.rb` of every gem.
  def initialize(name, version, platforms, uuid, ghsa, work, mark)
    @name = name
    @version = version
    @uuid = uuid
    @ghsa = ghsa
    @work = work
    @mark = mark
    @requests = []
    @lock = Mutex.new
    @patch_routes_up = true
    FileUtils.mkdir_p(@work)
    @ruby_gem = repack(nil)
    @prebuilds = platforms.sort.map { |platform| repack(platform) }
    @server = TCPServer.new("127.0.0.1", 0)
    @thread = Thread.new { loop { serve(@server.accept) } }
  end

  def url
    "http://127.0.0.1:#{@server.addr[1]}"
  end

  def index_url
    "#{url}/patch-registry/gem/#{TOKEN}/#{@uuid}/"
  end

  def stop
    @thread.kill
    @server.close
  end

  # From now on the registry and the downloads answer 503: what a machine
  # without access to the patch service sees.
  def take_down
    @lock.synchronize { @patch_routes_up = false }
  end

  def bring_up
    @lock.synchronize { @patch_routes_up = true }
  end

  # [verb, path, status] of every request so far.
  def requests
    @lock.synchronize { @requests.dup }
  end

  def forget_requests
    @lock.synchronize { @requests.clear }
  end

  def sha256_of(platform)
    (@prebuilds.find { |b| b.platform == platform } || @ruby_gem).sha256
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

  # The upstream gem of `platform` (nil: the ruby gem) with the mark appended
  # to `lib/<name>.rb`, and the facts the index and the API state about it.
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
    bytes = out.string
    deps = spec.runtime_dependencies.map { |d| "#{d.name}:#{d.requirement.as_list.join('&')}" }.sort.join(",")
    Built.new(file, platform ? "#{@version}-#{platform}" : @version, platform, bytes,
              Digest::SHA256.hexdigest(bytes), "sha512-" + [Digest::SHA512.digest(bytes)].pack("m0"),
              spec.to_ruby, deps, spec.required_ruby_version.as_list.join("&"),
              spec.required_rubygems_version.as_list.join("&"))
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

  # ---- the routes ----------------------------------------------------------

  def all_gems
    [@ruby_gem] + @prebuilds
  end

  def info_body
    lines = all_gems.map do |g|
      "#{g.token} #{g.deps}|checksum:#{g.sha256},ruby:#{g.ruby},rubygems:#{g.rubygems}\n"
    end
    "---\n" + lines.join
  end

  def base_purl
    "pkg:gem/#{@name}@#{@version}"
  end

  def patch_purl
    "#{base_purl}?platform=ruby"
  end

  def vulnerabilities
    { @ghsa => { "cves" => [], "summary" => "nokogiri end-to-end test", "severity" => "high",
                 "description" => "nokogiri end-to-end test" } }
  end

  def artifact_url(leaf)
    "#{url}/artifacts/#{@uuid}/#{leaf}"
  end

  def package_result
    artifacts = [{ "kind" => "tarball", "url" => artifact_url(@ruby_gem.file),
                   "contentType" => "application/octet-stream", "sizeBytes" => @ruby_gem.bytes.bytesize,
                   "integrity" => { "sha512" => @ruby_gem.sri, "sha256" => @ruby_gem.sha256 } }]
    @prebuilds.each do |g|
      stub_leaf = g.file.sub(/\.gem\z/, ".gemspec")
      artifacts << { "kind" => "gem-platform", "platform" => g.platform, "url" => artifact_url(g.file),
                     "contentType" => "application/octet-stream", "sizeBytes" => g.bytes.bytesize,
                     "integrity" => { "sha512" => g.sri, "sha256" => g.sha256 } }
      artifacts << { "kind" => "gem-platform-stub-gemspec", "platform" => g.platform,
                     "url" => artifact_url(stub_leaf), "contentType" => "text/plain",
                     "sizeBytes" => g.stub.bytesize, "integrity" => { "sha512" => sri(g.stub) } }
    end
    {
      "status" => "granted",
      "url" => "#{url}/patch/gem/#{@name}/#{@version}/#{TOKEN}/#{@uuid}/#{@ruby_gem.file}",
      "purl" => patch_purl,
      "artifacts" => artifacts,
      "registryOverride" => {
        "kind" => "rubygems-compact-index",
        "indexUrl" => index_url,
        "identifiers" => {
          "name" => @name, "version" => @version, "gemChecksumSha256" => @ruby_gem.sha256,
          "gemPlatforms" => @prebuilds.map { |g| { "platform" => g.platform, "gemChecksumSha256" => g.sha256 } }
        }
      }
    }
  end

  def json(body)
    [200, "application/json", JSON.generate(body)]
  end

  # status, content type, body of the answer to `verb path`.
  def respond(verb, path)
    api = "/v0/orgs/#{ORG}/patches"
    registry = "/patch-registry/gem/#{TOKEN}/#{@uuid}"
    if verb == "POST" && path == "#{api}/batch"
      return json("packages" => [{ "purl" => base_purl, "patches" => [{
                    "uuid" => @uuid, "purl" => patch_purl, "tier" => "free", "cveIds" => [],
                    "ghsaIds" => [@ghsa], "severity" => "high", "title" => "nokogiri end-to-end test"
                  }] }], "canAccessPaidPatches" => false)
    elsif path.start_with?("#{api}/by-package/")
      return json("patches" => [{ "uuid" => @uuid, "purl" => patch_purl,
                                  "publishedAt" => "2026-02-01T00:00:00Z", "description" => "nokogiri end-to-end test",
                                  "license" => "MIT", "tier" => "free", "vulnerabilities" => vulnerabilities }],
                  "canAccessPaidPatches" => false)
    elsif path == "#{api}/view/#{@uuid}"
      return json("uuid" => @uuid, "purl" => patch_purl, "publishedAt" => "2026-02-01T00:00:00Z",
                  "files" => { "lib/#{@name}.rb" => { "beforeHash" => git_sha256(@before),
                                                      "afterHash" => git_sha256(@after) } },
                  "vulnerabilities" => vulnerabilities, "description" => "nokogiri end-to-end test",
                  "license" => "MIT", "tier" => "free")
    elsif verb == "POST" && path == "#{api}/package"
      return json("results" => { @uuid => package_result })
    end

    serves_patch = path.start_with?(registry) || path.start_with?("/artifacts/") || path.start_with?("/patch/")
    return [404, "text/plain", ""] unless serves_patch
    return [503, "text/plain", ""] unless @lock.synchronize { @patch_routes_up }

    info = info_body
    case path
    when "#{registry}/versions"
      tokens = all_gems.map(&:token).join(",")
      [200, "text/plain", "created_at: 2026-01-01T00:00:00Z\n---\n#{@name} #{tokens} #{Digest::MD5.hexdigest(info)}\n"]
    when "#{registry}/info/#{@name}" then [200, "text/plain", info]
    when "#{registry}/names" then [200, "text/plain", "---\n#{@name}\n"]
    else
      leaf = File.basename(path)
      gem = all_gems.find { |g| g.file == leaf }
      stub = @prebuilds.find { |g| g.file.sub(/\.gem\z/, ".gemspec") == leaf }
      if gem then [200, "application/octet-stream", gem.bytes]
      elsif stub then [200, "text/plain", stub.stub]
      else [404, "text/plain", ""]
      end
    end
  end

  def serve(socket)
    line = socket.gets
    return unless line
    verb, target, = line.split(" ")
    length = 0
    while (header = socket.gets) && header != "\r\n"
      key, value = header.split(":", 2)
      length = value.to_i if key.casecmp("content-length").zero?
    end
    socket.read(length) if length > 0
    path = target.to_s.split("?").first
    status, type, body = respond(verb, path)
    @lock.synchronize { @requests << [verb, path, status] }
    reason = { 200 => "OK", 404 => "Not Found", 503 => "Service Unavailable" }.fetch(status)
    socket.write("HTTP/1.1 #{status} #{reason}\r\nContent-Type: #{type}\r\n" \
                 "Content-Length: #{body.bytesize}\r\nETag: \"#{Digest::MD5.hexdigest(body)}\"\r\n" \
                 "Connection: close\r\n\r\n")
    socket.write(body) unless verb == "HEAD"
  rescue StandardError
    nil
  ensure
    socket.close
  end
end
