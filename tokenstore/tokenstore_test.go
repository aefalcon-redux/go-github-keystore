package tokenstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/messagestore"
	//"github.com/golang/protobuf/ptypes"
)

type MockProvider struct {
}

const TOKEN_LEN = 32

func GenJwtToken(app uint64) string {
	header := map[string]string{
		"typ": "jwt",
		"alg": "RS256",
	}
	claims := map[string]interface{}{
		"sub": fmt.Sprintf("%d", app),
		"exp": 2168376152,
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	header64 := base64.RawURLEncoding.EncodeToString(headerJson)
	claims64 := base64.RawURLEncoding.EncodeToString(claimsJson)
	var signature [32]byte
	_, err = rand.Read(signature[:])
	if err != nil {
		panic(err)
	}
	signature64 := base64.RawURLEncoding.EncodeToString(signature[:])
	token := strings.Join([]string{header64, claims64, signature64}, ".")
	return token
}

func GenInstallToken() string {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		panic(err)
	}
	token64 := base64.RawURLEncoding.EncodeToString(token[:])
	return token64
}

func (p *MockProvider) SignJwt(req *appkeypb.SignJwtRequest, logger kslog.KsLogger) (*appkeypb.SignJwtResponse, error) {
	resp := appkeypb.SignJwtResponse{
		Jwt: GenJwtToken(req.App),
	}
	return &resp, nil
}

func (p *MockProvider) InstallTokenProvider(install uint64, appToken string) (string, time.Time, error) {
	expire := time.Now().Add(time.Hour * 24 * 365)
	return GenInstallToken(), expire, nil
}

func NewMemTokenStore() *TokenMessageStore {
	messageStore := messagestore.BlobMessageStore{
		BlobStore: messagestore.NewMemBlobStore(),
	}
	return &TokenMessageStore{
		MessageStore: &messageStore,
		Links:        tokenpb.DefaultLinks,
	}
}

func TestGetInstallToken(t *testing.T) {
	provider := MockProvider{}
	const appId = 1
	const installId = 1
	store := NewMemTokenStore()
	logger := kslog.KsTestLogger{
		TestLogger: t,
	}
	service := InstallTokenService{
		TokenMessageStore:    store,
		SigningService:       &provider,
		InstallTokenProvider: provider.InstallTokenProvider,
	}
	req := tokenpb.GetInstallTokenRequest{
		App:     appId,
		Install: installId,
	}
	resp, err := service.GetInstallToken(&req, &logger)
	if err != nil {
		t.Fatalf("Failed to get token: %s", err)
	}
	if resp.Token == nil {
		t.Fatalf("Response contained nil token: %s", err)
	}
}
