package docstore

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/timeutils"
	structpb "github.com/golang/protobuf/ptypes/struct"
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

func TestAddAppWithKey(t *testing.T) {
	keyStore := NewMemKeyStore()
	logger := kslog.KsTestLogger{
		TestLogger: t,
	}
	err := keyStore.InitDb(&logger)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}
	keyFileName := filepath.Join("testdata", "priv1.pem")
	keyFile, err := os.Open(keyFileName)
	if err != nil {
		t.Fatalf("Failed to open file %s: %s", keyFileName, err)
	}
	keyBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		t.Fatalf("Failed to read file %s: %s", keyFileName, err)
	}
	rsaKey, err := keyutils.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse key from file %s: %s", keyFileName, err)
	}
	fingerprint, err := keyutils.KeyFingerprint(rsaKey)
	if err != nil {
		t.Fatalf("Failed to derive fingerprint of key from fiel %s: %s", keyFileName, err)
	}
	const appId = 1
	addReq := appkeypb.AddAppRequest{
		App: uint64(appId),
		Keys: []*appkeypb.AppKey{
			&appkeypb.AppKey{
				Key: keyBytes,
				Meta: &appkeypb.AppKeyMeta{
					Fingerprint: fingerprint,
				},
			},
		},
	}
	_, err = keyStore.AddApp(&addReq, &logger)
	if err != nil {
		t.Fatalf("Failed to add app %d: %s", appId, err)
	}
	getAppReq := appkeypb.GetAppRequest{
		App: uint64(appId),
	}
	appBack, err := keyStore.GetApp(&getAppReq, &logger)
	if err != nil {
		t.Fatalf("Failed to get app document back: %s", err)
	}
	if len(appBack.Keys) == 0 {
		t.Fatal("No key on app")
	}
	if len(appBack.Keys) > 1 {
		t.Fatal("app has more than one key")
	}
	var fingerprintBack string
	for fingerprintBack = range appBack.Keys {
	}
	keyBack := appBack.Keys[fingerprintBack]
	if fingerprintBack != fingerprint {
		t.Fatalf("index fingerprint %s does not match expected fingerprint %s", fingerprintBack, fingerprint)
	}
	if keyBack.Meta.Fingerprint != fingerprint {
		t.Fatalf("fingerprint %s does not match expected fingerprint %s", fingerprintBack, fingerprint)
	}
}

func TestSignJwt(t *testing.T) {
	keyStore := NewMemKeyStore()
	logger := kslog.KsTestLogger{
		TestLogger: t,
	}
	err := keyStore.InitDb(&logger)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}
	keyFileName := filepath.Join("testdata", "priv1.pem")
	keyFile, err := os.Open(keyFileName)
	if err != nil {
		t.Fatalf("Failed to open file %s: %s", keyFileName, err)
	}
	keyBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		t.Fatalf("Failed to read file %s: %s", keyFileName, err)
	}
	rsaKey, err := keyutils.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse key from file %s: %s", keyFileName, err)
	}
	fingerprint, err := keyutils.KeyFingerprint(rsaKey)
	if err != nil {
		t.Fatalf("Failed to derive fingerprint of key from fiel %s: %s", keyFileName, err)
	}
	const appId = 1
	addReq := appkeypb.AddAppRequest{
		App: uint64(appId),
		Keys: []*appkeypb.AppKey{
			&appkeypb.AppKey{
				Key: keyBytes,
				Meta: &appkeypb.AppKeyMeta{
					Fingerprint: fingerprint,
				},
			},
		},
	}
	_, err = keyStore.AddApp(&addReq, &logger)
	if err != nil {
		t.Fatalf("Failed to add app %d: %s", appId, err)
	}
	now := time.Now().UTC()
	signReq := appkeypb.SignJwtRequest{
		App:       appId,
		Algorithm: "RS256",
		Claims: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"iss": &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: fmt.Sprintf("%d", appId),
					},
				},
				"exp": &structpb.Value{
					Kind: &structpb.Value_NumberValue{
						NumberValue: timeutils.TimeToFloat(now.Add(time.Hour)),
					},
				},
			},
		},
	}
	jwtResp, err := keyStore.SignJwt(&signReq, logger)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %s", err)
	}
	if jwtResp.Jwt == "" {
		t.Fatalf("response has no JWT")
	}
	t.Logf("issued JWT %s", string(jwtResp.Jwt))
	secureData64 := jwtResp.Jwt[:strings.LastIndex(jwtResp.Jwt, ".")]
	sig64 := jwtResp.Jwt[len(secureData64)+1:]
	sig := make([]byte, base64.RawURLEncoding.DecodedLen(len(sig64)))
	base64.RawURLEncoding.Decode(sig, []byte(sig64))
	digest := sha256.Sum256([]byte(secureData64))
	err = rsa.VerifyPKCS1v15(rsaKey.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig)
	if err != nil {
		t.Fatalf("Failed to verify signature: %s", err)
	}
	t.Log("signiture verifies")
}
