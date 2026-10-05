// Package psa is a Go binding for the advisory password-security-analyzer (psa-core).
//
// Does not authorize account creation.
package psa

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../include
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -L${SRCDIR}/../../target/release -lpsa_ffi -Wl,-rpath,${SRCDIR}/lib/linux_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -L${SRCDIR}/../../target/release -lpsa_ffi
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -L${SRCDIR}/../../target/release -lpsa_ffi
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -L${SRCDIR}/../../target/release -lpsa_ffi
#include "psa.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"
)

// Result mirrors AnalyzeResult JSON from psa-core.
type Result map[string]any

func lastError() error {
	msg := C.GoString(C.psa_last_error())
	if msg == "" {
		return errors.New("psa-ffi error")
	}
	return errors.New(msg)
}

func takeJSON(ptr *C.char) (Result, error) {
	if ptr == nil {
		return nil, lastError()
	}
	defer C.psa_string_free(ptr)
	var out Result
	if err := json.Unmarshal([]byte(C.GoString(ptr)), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func cOptions(options map[string]any) (*C.char, func()) {
	if options == nil {
		return nil, func() {}
	}
	b, err := json.Marshal(options)
	if err != nil {
		return nil, func() {}
	}
	c := C.CString(string(b))
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// AnalyzeOffline scores without network HIBP unless hibp_offline is set.
func AnalyzeOffline(password string, options map[string]any) (Result, error) {
	cpw := C.CString(password)
	defer C.free(unsafe.Pointer(cpw))
	copt, freeOpt := cOptions(options)
	defer freeOpt()
	return takeJSON(C.psa_analyze_offline(cpw, copt))
}

// Analyze scores with live HIBP unless skip_breach / hibp_offline.
func Analyze(password string, options map[string]any) (Result, error) {
	cpw := C.CString(password)
	defer C.free(unsafe.Pointer(cpw))
	copt, freeOpt := cOptions(options)
	defer freeOpt()
	return takeJSON(C.psa_analyze(cpw, copt))
}

// CheckPwned returns breach JSON only.
func CheckPwned(password string, options map[string]any) (Result, error) {
	cpw := C.CString(password)
	defer C.free(unsafe.Pointer(cpw))
	copt, freeOpt := cOptions(options)
	defer freeOpt()
	return takeJSON(C.psa_check_pwned(cpw, copt))
}

// ModelInfo returns build metadata.
func ModelInfo() (Result, error) {
	return takeJSON(C.psa_model_info())
}
