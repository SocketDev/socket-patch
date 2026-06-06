# frozen_string_literal: true

# RubyGems distribution of the `socket-patch` CLI. A thin launcher gem: on first
# run it downloads the prebuilt binary for the host platform from the matching
# GitHub release (`v<version>`), verifies it against SHA256SUMS, caches it, and
# execs it. `gem install socket-patch` therefore puts `socket-patch` on PATH —
# useful in Bundler/Ruby environments where the gem ecosystem's setup hook needs
# the CLI present. Set `SOCKET_PATCH_BIN` to an existing binary to skip the
# download (airgapped CI). The version is synced with the workspace by
# `scripts/version-sync.sh`.
Gem::Specification.new do |s|
  s.name        = "socket-patch"
  s.version     = "3.3.0"
  s.summary     = "CLI tool for applying security patches to dependencies."
  s.description = "Launcher gem for the socket-patch CLI: downloads the prebuilt binary for the " \
                  "host platform from the matching GitHub release, verifies its SHA-256, caches " \
                  "it, and execs it. Set SOCKET_PATCH_BIN to bypass the download."
  s.authors     = ["Socket Security"]
  s.license     = "MIT"
  s.homepage    = "https://github.com/SocketDev/socket-patch"
  s.files       = ["lib/socket_patch/launcher.rb", "exe/socket-patch", "README.md"]
  s.bindir      = "exe"
  s.executables = ["socket-patch"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 2.6.0"
  s.metadata = {
    "source_code_uri" => "https://github.com/SocketDev/socket-patch",
    "rubygems_mfa_required" => "true",
  }
end
