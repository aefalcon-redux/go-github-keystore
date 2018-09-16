package docstore

import (
	"fmt"
	"testing"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/kslog"
)

var TestBucket string
var TestRegion string

func NewMemKeyStore() *AppKeyStore {
	blobStore := NewMemBlobStore()
	docStore := BlobDocStore{
		BlobStore: blobStore,
	}
	return NewAppKeyStore(&docStore, nil)
}

func TestInitDb(t *testing.T) {
	keyStore := NewMemKeyStore()
	logger := kslog.KsTestLogger{
		TestLogger:  t,
		FailOnError: false,
	}
	err := keyStore.InitDb(&logger)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}
}

func TestAddApp(t *testing.T) {
	keyStore := NewMemKeyStore()
	logger := kslog.KsTestLogger{
		TestLogger: t,
	}
	err := keyStore.InitDb(&logger)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}
	testAddAppWithId := func(shouldPass bool, appId uint64, t *testing.T) {
		req := appkeypb.AddAppRequest{
			App: appId,
		}
		_, err = keyStore.AddApp(&req, &logger)
		if err != nil && shouldPass {
			t.Errorf("Failed to add app: %s", err)
		} else if err != nil && !shouldPass {
			// expected failure
		} else if err == nil && !shouldPass {
			t.Errorf("Test unexpectedly passed")
		} else if err == nil && shouldPass {
			// exected pass
		} else {
			panic("unexpected code path")
		}
	}
	testSpecs := []struct {
		appId         uint64
		shouldSucceed bool
	}{
		{0, false},
		{1, true},
		{2, true},
		{3, true},
	}
	for _, testSpec := range testSpecs {
		var stateMsg string
		if testSpec.shouldSucceed {
			stateMsg = "succeeds"
		} else {
			stateMsg = "fails"
		}
		testName := fmt.Sprintf("Add app %d %s", testSpec.appId, stateMsg)
		testFunc := func(t *testing.T) { testAddAppWithId(testSpec.shouldSucceed, testSpec.appId, t) }
		t.Run(testName, testFunc)
	}
}

func TestRemoveApp(t *testing.T) {
	keyStore := NewMemKeyStore()
	logger := kslog.KsTestLogger{
		TestLogger: t,
	}
	err := keyStore.InitDb(&logger)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}
	for i := 1; i < 3; i++ {
		addReq := appkeypb.AddAppRequest{
			App: uint64(i),
		}
		_, err := keyStore.AddApp(&addReq, &logger)
		if err != nil {
			t.Fatalf("Failed to add app %d: %s", i, err)
		}
	}
	testRemoveAppWithId := func(shouldPass bool, appId uint64, t *testing.T) {
		remReq := appkeypb.RemoveAppRequest{
			App: appId,
		}
		_, err = keyStore.RemoveApp(&remReq, &logger)
		if err != nil && shouldPass {
			t.Errorf("Failed to add app: %s", err)
		} else if err != nil && !shouldPass {
			// expected failure
		} else if err == nil && !shouldPass {
			t.Errorf("Test unexpectedly passed")
		} else if err == nil && shouldPass {
			// exected pass
		} else {
			panic("unexpected code path")
		}
	}
	testSpecs := []struct {
		appId         uint64
		shouldSucceed bool
	}{
		{0, false},
		{1, true},
		{2, true},
		{3, false},
	}
	for _, testSpec := range testSpecs {
		var stateMsg string
		if testSpec.shouldSucceed {
			stateMsg = "succeeds"
		} else {
			stateMsg = "fails"
		}
		testName := fmt.Sprintf("Remove app %d %s", testSpec.appId, stateMsg)
		testFunc := func(t *testing.T) { testRemoveAppWithId(testSpec.shouldSucceed, testSpec.appId, t) }
		t.Run(testName, testFunc)
	}
}
