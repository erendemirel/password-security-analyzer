package com.psa;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Advisory password strength analyzer (JNA → psa-ffi).
 * Does not authorize account creation.
 */
public final class PasswordSecurityAnalyzer {
    private PasswordSecurityAnalyzer() {}

    public interface PsaFfi extends Library {
        Pointer psa_analyze_offline(String password, String optionsJson);
        Pointer psa_analyze(String password, String optionsJson);
        Pointer psa_check_pwned(String password, String optionsJson);
        Pointer psa_model_info();
        void psa_string_free(Pointer s);
        String psa_last_error();
    }

    private static final Gson GSON = new Gson();
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();
    private static final PsaFfi LIB = load();

    private static PsaFfi load() {
        String env = System.getenv("PSA_FFI_PATH");
        if (env != null && !env.isBlank()) {
            return Native.load(env, PsaFfi.class);
        }
        Path[] candidates = new Path[] {
            Path.of("src/main/resources/native/psa_ffi.dll"),
            Path.of("src/main/resources/native/libpsa_ffi.so"),
            Path.of("src/main/resources/native/libpsa_ffi.dylib"),
            Path.of("../../target/release/psa_ffi.dll"),
            Path.of("../../target/release/libpsa_ffi.so"),
            Path.of("../../target/release/libpsa_ffi.dylib"),
        };
        for (Path p : candidates) {
            if (Files.isRegularFile(p)) {
                return Native.load(p.toAbsolutePath().toString(), PsaFfi.class);
            }
        }
        // Fallback: name lookup on java.library.path
        return Native.load("psa_ffi", PsaFfi.class);
    }

    private static Map<String, Object> call(Pointer ptr) {
        if (ptr == null) {
            String err = LIB.psa_last_error();
            throw new IllegalStateException(err == null || err.isEmpty() ? "psa-ffi error" : err);
        }
        try {
            String json = ptr.getString(0, "utf8");
            Map<String, Object> out = GSON.fromJson(json, MAP_TYPE);
            return out != null ? out : new HashMap<>();
        } finally {
            LIB.psa_string_free(ptr);
        }
    }

    private static String optionsJson(Map<String, Object> options) {
        return options == null ? null : GSON.toJson(options);
    }

    public static Map<String, Object> analyzeOffline(String password, Map<String, Object> options) {
        return call(LIB.psa_analyze_offline(password, optionsJson(options)));
    }

    public static Map<String, Object> analyze(String password, Map<String, Object> options) {
        return call(LIB.psa_analyze(password, optionsJson(options)));
    }

    public static Map<String, Object> checkPwned(String password, Map<String, Object> options) {
        return call(LIB.psa_check_pwned(password, optionsJson(options)));
    }

    public static Map<String, Object> modelInfo() {
        return call(LIB.psa_model_info());
    }
}
