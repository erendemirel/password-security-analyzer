# frozen_string_literal: true

require "json"
require "ffi"
require "pathname"

# Advisory password strength analyzer (FFI → psa-ffi / psa-core).
# Does not authorize account creation.
module PasswordSecurityAnalyzer
  class Error < StandardError; end

  module Lib
    extend FFI::Library

    def self.lib_candidates
      here = Pathname(__dir__).expand_path
      repo = here.join("../../..").expand_path # packages/psa-ruby/lib → repo
      env = ENV["PSA_FFI_PATH"]
      out = []
      out << Pathname(env) if env && !env.empty?

      lib_dir = here.join("native")
      case FFI::Platform::OS
      when "windows"
        out << lib_dir.join("psa_ffi.dll")
        out << repo.join("target/release/psa_ffi.dll")
      when "darwin"
        out << lib_dir.join("libpsa_ffi.dylib")
        out << repo.join("target/release/libpsa_ffi.dylib")
      else
        out << lib_dir.join("libpsa_ffi.so")
        out << repo.join("target/release/libpsa_ffi.so")
      end
      out
    end

    path = lib_candidates.find(&:exist?)
    unless path
      raise Error,
            "psa_ffi shared library not found. Build with:\n" \
            "  pwsh scripts/build_ffi.ps1   # or scripts/build_ffi.sh\n" \
            "Or set PSA_FFI_PATH to the .dll/.so/.dylib"
    end

    ffi_lib path.to_s

    attach_function :psa_analyze_offline, %i[string string], :pointer
    attach_function :psa_analyze, %i[string string], :pointer
    attach_function :psa_check_pwned, %i[string string], :pointer
    attach_function :psa_model_info, [], :pointer
    attach_function :psa_string_free, [:pointer], :void
    attach_function :psa_last_error, [], :string
  end
  private_constant :Lib

  module_function

  def analyze_offline(password, options = nil)
    call(:psa_analyze_offline, password, options)
  end

  def analyze(password, options = nil)
    call(:psa_analyze, password, options)
  end

  def check_pwned(password, options = nil)
    call(:psa_check_pwned, password, options)
  end

  def model_info
    ptr = Lib.psa_model_info
    take_json(ptr)
  end

  def call(fn, password, options)
    opt = options.nil? ? nil : JSON.generate(options)
    ptr = Lib.send(fn, password, opt)
    take_json(ptr)
  end
  private_class_method :call

  def take_json(ptr)
    if ptr.null?
      err = Lib.psa_last_error
      raise Error, (err && !err.empty? ? err : "psa-ffi error")
    end
    begin
      raw = ptr.read_string
      raise Error, "null JSON from psa-ffi" if raw.nil? || raw.empty?

      JSON.parse(raw)
    ensure
      Lib.psa_string_free(ptr)
    end
  end
  private_class_method :take_json
end
