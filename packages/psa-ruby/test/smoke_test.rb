# frozen_string_literal: true

require "json"
require "pathname"

root = Pathname(__dir__).join("..").expand_path
$LOAD_PATH.unshift(root.join("lib").to_s)

begin
  require "ffi"
rescue LoadError
  warn "Install deps first: cd packages/psa-ruby && bundle install"
  raise
end

require "password_security_analyzer"

info = PasswordSecurityAnalyzer.model_info
raise "advisory=#{info['advisory'].inspect}" unless info["advisory"] == true

weak = PasswordSecurityAnalyzer.analyze_offline("password")
raise "password label=#{weak['label'].inspect}" unless weak["label"] == "weak"

alpha = PasswordSecurityAnalyzer.analyze_offline("abcdefghijklmnopqrstuvwxyz")
raise "alphabet label=#{alpha['label'].inspect}" unless alpha["label"] == "weak"
reasons = alpha["reasons"] || []
raise "reasons=#{reasons.inspect}" unless reasons.include?("sequential_run")

puts "ruby smoke OK"
