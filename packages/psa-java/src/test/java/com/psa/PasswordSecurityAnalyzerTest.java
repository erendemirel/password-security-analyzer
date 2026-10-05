package com.psa;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PasswordSecurityAnalyzerTest {
    @Test
    void offlineSmoke() {
        Map<String, Object> info = PasswordSecurityAnalyzer.modelInfo();
        assertEquals(Boolean.TRUE, info.get("advisory"));

        Map<String, Object> weak = PasswordSecurityAnalyzer.analyzeOffline("password", null);
        assertEquals("weak", weak.get("label"));

        Map<String, Object> alpha = PasswordSecurityAnalyzer.analyzeOffline(
                "abcdefghijklmnopqrstuvwxyz", null);
        assertEquals("weak", alpha.get("label"));
        @SuppressWarnings("unchecked")
        List<String> reasons = (List<String>) alpha.get("reasons");
        assertNotNull(reasons);
        assertTrue(reasons.contains("sequential_run"));
    }
}
