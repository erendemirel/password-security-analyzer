package psa_test

import (
	"testing"

	psa "github.com/example/password-security-analyzer/packages/psa-go"
)

func TestOfflineSmoke(t *testing.T) {
	info, err := psa.ModelInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info["advisory"] != true {
		t.Fatalf("advisory: %v", info)
	}

	r, err := psa.AnalyzeOffline("password", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r["label"] != "weak" {
		t.Fatalf("password label=%v", r["label"])
	}

	a, err := psa.AnalyzeOffline("abcdefghijklmnopqrstuvwxyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a["label"] != "weak" {
		t.Fatalf("alphabet label=%v", a["label"])
	}
}
