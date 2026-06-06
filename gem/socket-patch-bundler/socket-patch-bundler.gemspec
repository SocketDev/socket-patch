# frozen_string_literal: true

# Published form of the socket-patch Bundler plugin (CLI_CONTRACT property:
# "gem" support matrix, Phase 2). `socket-patch setup` today references the
# in-tree plugin under `.socket/bundler-plugin/` via `git:`; once this gem is
# published, a follow-up switches the Gemfile directive to
# `plugin "socket-patch-bundler", "~> <major.minor>"`. The version is kept in
# sync with the workspace by `scripts/version-sync.sh`.
Gem::Specification.new do |s|
  s.name        = "socket-patch-bundler"
  s.version     = "3.3.0"
  s.summary     = "Bundler plugin that keeps socket-patch gem patches applied on every bundle install."
  s.description = "Re-applies the gem patches recorded in a project's .socket/manifest.json on " \
                  "every `bundle install` (cached and fresh) by invoking the socket-patch CLI. " \
                  "The CLI must be on PATH (or pointed at by SOCKET_PATCH_BIN)."
  s.authors     = ["Socket"]
  s.license     = "MIT"
  s.homepage    = "https://github.com/SocketDev/socket-patch"
  s.files       = ["plugins.rb", "README.md"]
  s.required_ruby_version = ">= 2.6.0"
  s.metadata = {
    "source_code_uri" => "https://github.com/SocketDev/socket-patch",
    "rubygems_mfa_required" => "true",
  }
end
