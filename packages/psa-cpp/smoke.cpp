// Smoke test for packages/psa-cpp
#include "psa.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

static bool contains(const std::string &hay, const std::string &needle) {
  return hay.find(needle) != std::string::npos;
}

int main() {
  try {
    auto info = psa::model_info();
    if (!contains(info, "\"advisory\":true") && !contains(info, "\"advisory\": true")) {
      std::cerr << "bad model_info: " << info << "\n";
      return 1;
    }

    auto weak = psa::analyze_offline("password");
    if (!contains(weak, "\"label\":\"weak\"")) {
      std::cerr << "password: " << weak << "\n";
      return 1;
    }

    auto alpha = psa::analyze_offline("abcdefghijklmnopqrstuvwxyz");
    if (!contains(alpha, "\"label\":\"weak\"") || !contains(alpha, "sequential_run")) {
      std::cerr << "alphabet: " << alpha << "\n";
      return 1;
    }

    std::cout << "cpp smoke OK\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
