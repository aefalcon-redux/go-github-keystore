package tokenstore

import (
	"encoding/base64"
	"math/rand"
	"testing"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aefalcon/go-github-keystore/kslog"
)

type MockProvider struct {
	AppTokens        map[uint64][]byte
	AppInstallTokens map[uint64]map[uint64][]byte
}

const TOKEN_LEN = 32

func GenToken() []byte {
	var token [TOKEN_LEN]byte
	_, err := rand.Read(token[:])
	if err != nil {
		panic(err)
	}
	len64 := base64.RawURLEncoding.EncodedLen(len(token))
	token64 := make([]byte, len64)
	base64.RawURLEncoding.Encode(token64, token[:])
	return token64
}

func (p *MockProvider) requireAppTokens() {
	if p.AppTokens == nil {
		p.AppTokens = make(map[uint64][]byte)
	}
}

func (p *MockProvider) requireAppInstallTokens() {
	if p.AppInstallTokens == nil {
		p.AppInstallTokens = make(map[uint64]map[uint64][]byte)
	}
}

func (p *MockProvider) AppTokenProvider(app uint64) ([]byte, time.Time, error) {
	p.requireAppTokens()
	expire := time.Now().Add(time.Hour * 24 * 365)
	token := p.AppTokens[app]
	if token == nil {
		token = GenToken()

		p.AppTokens[app] = token
	}
	return token, expire, nil
}

func (p *MockProvider) InstallTokenProvider(app, install uint64) ([]byte, time.Time, error) {
	p.requireAppInstallTokens()
	expire := time.Now().Add(time.Hour * 24 * 365)
	installTokens := p.AppInstallTokens[app]
	if installTokens == nil {
		installTokens = make(map[uint64][]byte)
		p.AppInstallTokens[app] = installTokens
	}
	token := installTokens[install]
	if token == nil {
		token = GenToken()
		installTokens[install] = token
	}
	return token, expire, nil
}

func (p *MockProvider) InstallToken(app, install uint64) []byte {
	installTokens := p.AppInstallTokens[app]
	if installTokens == nil {
		return nil
	}
	return installTokens[install]
}

func TestMockProvider(t *testing.T) {
	provider := MockProvider{}
	const appId = 1
	const installId = 1
	token1, _, err := provider.InstallTokenProvider(appId, installId)
	if err != nil {
		t.Fatalf("failed to get first token: %s", err)
	}
	token2 := provider.InstallToken(appId, installId)
	if string(token1) != string(token2) {
		t.Fatalf("2nd token %v does not match %v", string(token2), string(token1))
	}
}

func NewMemTokenStore() *TokenDocStore {
	blobStore := docstore.NewMemBlobStore()
	docStore := docstore.BlobDocStore{
		BlobStore: blobStore,
	}
	return NewTokenDocStore(&docStore, nil)
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
		TokenDocStore:        store,
		AppTokenProvider:     provider.AppTokenProvider,
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
