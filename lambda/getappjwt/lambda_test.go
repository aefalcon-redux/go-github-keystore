package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/appkeystore"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/timeutils"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
)

func NewMemKeyStore() *appkeystore.AppKeyStore {
	blobStore := docstore.NewMemBlobStore()
	docStore := docstore.BlobDocStore{
		BlobStore: blobStore,
	}
	return appkeystore.NewAppKeyStore(&docStore, nil)
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
						NumberValue: float64(int64(timeutils.TimeToFloat(now.Add(time.Minute * 10)))),
					},
				},
			},
		},
	}
	marshaler := jsonpb.Marshaler{}
	reqJson, err := marshaler.MarshalToString(&signReq)
	if err != nil {
		t.Fatalf("Failed to marshal request json: %s", err)
	}
	t.Logf("using request json: %s", reqJson)
	lambdaReq := LambdaSignJwtRequest{}
	err = json.Unmarshal([]byte(reqJson), &lambdaReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal protobuf json into lambda request object: %s", err)
	}
	resp, err := HandleRequest(keyStore, context.Background(), &lambdaReq)
	if err != nil {
		t.Fatalf("handler failure: %s", err)
	}
	var jwtResp appkeypb.SignJwtResponse
	err = jsonpb.UnmarshalString(resp, &jwtResp)
	if err != nil {
		t.Fatalf("Failed to unmarshal json response: %s", err)
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
