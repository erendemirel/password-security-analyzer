#pragma once

/**
 * Thin C++ wrapper around the psa-ffi C ABI.
 * Advisory only — does not authorize account creation.
 *
 * Link with -lpsa_ffi and ensure the shared library is on the loader path.
 */

#include "psa.h"

#include <stdexcept>
#include <string>

namespace psa {

inline std::string last_error() {
  const char *e = psa_last_error();
  return e ? std::string(e) : std::string("psa-ffi error");
}

inline std::string take_json(char *ptr) {
  if (!ptr) {
    throw std::runtime_error(last_error());
  }
  std::string out(ptr);
  psa_string_free(ptr);
  return out;
}

/** Offline analyze; options_json may be nullptr or a JSON object string. */
inline std::string analyze_offline(const std::string &password,
                                   const char *options_json = nullptr) {
  return take_json(psa_analyze_offline(password.c_str(), options_json));
}

inline std::string analyze(const std::string &password,
                           const char *options_json = nullptr) {
  return take_json(::psa_analyze(password.c_str(), options_json));
}

inline std::string check_pwned(const std::string &password,
                               const char *options_json = nullptr) {
  return take_json(psa_check_pwned(password.c_str(), options_json));
}

inline std::string model_info() { return take_json(psa_model_info()); }

} // namespace psa
