require "fileutils"
require "tmpdir"
require "json"

module Bundler
  class << self
    attr_accessor :root, :bundle_path
  end
  module Plugin
    def self.add_hook(*)
    end
  end
end

def assert(condition, message)
  raise message unless condition
end

Dir.mktmpdir("socket-patch-plugin-safety") do |root|
  Bundler.root = root
  Bundler.bundle_path = File.join(root, "bundle")
  plugin_dir = File.join(root, ".socket", "bundler-plugin")
  FileUtils.mkdir_p(plugin_dir)
  plugin = File.join(plugin_dir, "plugins.rb")
  FileUtils.cp(ARGV.fetch(0), plugin)
  load plugin

  gem_dir = File.join(Bundler.bundle_path, "gems", "example-1.0.0-platform")
  FileUtils.mkdir_p(gem_dir)
  literal = File.join(gem_dir, "file[1].rb")
  File.write(literal, "original")
  fifo = File.join(gem_dir, "pipe")
  assert(system("mkfifo", fifo), "could not create target FIFO")
  File.write(SocketPatch.manifest_path, JSON.generate("patches" => {
    "pkg:gem/example@1.0.0?platform=x#subpath" => {"files" => {
      "package/file[1].rb" => {}, "package/pipe" => {},
      "package/../outside" => {}, "/outside" => {}, "package/" => {}
    }},
    "pkg:gem/../../outside@1.0" => {"files" => {"file" => {}}}
  }))
  targets = SocketPatch.patch_target_files
  assert(targets.include?(literal), "literal glob characters lost platform target")
  assert(targets.include?(fifo), "FIFO target must be included without reading it")
  assert(targets.size == 4, "unsafe manifest paths escaped validation: #{targets.inspect}")
  before = SocketPatch.current_digest
  File.write(literal, "changed")
  assert(SocketPatch.current_digest != before, "platform target content absent from digest")

  stamp = SocketPatch.stamp_path
  assert(system("mkfifo", stamp), "could not create stamp FIFO")
  assert(!SocketPatch.stamped?("digest"), "FIFO cannot be a valid stamp")
  SocketPatch.write_stamp("digest")
  assert(File.file?(stamp) && File.read(stamp) == "digest", "FIFO stamp was not replaced")

  victim = File.join(root, "victim")
  File.write(victim, "keep")
  File.delete(stamp)
  File.symlink(victim, stamp)
  SocketPatch.write_stamp("next")
  assert(File.read(victim) == "keep", "stamp write followed symlink")
  File.delete(stamp)
  File.link(victim, stamp)
  SocketPatch.write_stamp("last")
  assert(File.read(victim) == "keep", "stamp write truncated a shared inode")
  assert(SocketPatch.stamped?("last"), "atomic stamp could not be read back")
end
