# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "password_security_analyzer"
  spec.version       = "0.1.0"
  spec.authors       = ["PSA"]
  spec.summary       = "Advisory password strength analyzer (FFI → psa-ffi)"
  spec.description   = "Does not authorize account creation. Calls the Rust psa-core engine via psa-ffi."
  spec.license       = "MIT"
  spec.files         = Dir["lib/**/*", "README.md"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 2.7.0"

  spec.add_dependency "ffi", "~> 1.15"
  spec.add_development_dependency "minitest", "~> 5.0"
end
