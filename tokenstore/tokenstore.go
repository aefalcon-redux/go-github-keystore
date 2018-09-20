package tokenstore

import (
	"fmt"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/golang/protobuf/ptypes"
	"github.com/jtacoma/uritemplates"
)

type AppTokenProvider func(app uint64) ([]byte, time.Time, error)
type InstallTokenProvider func(app, install uint8) ([]byte, time.Time, error)

type UnallowedAppId uint64

func (e UnallowedAppId) Error() string {
	return fmt.Sprintf("app id %d is not allowed", uint64(e))
}

type TokenDocStore struct {
	docstore.DocStore
	tokenpb.Links
}

func NewTokenDocStore(store docstore.DocStore, links *tokenpb.Links) *TokenDocStore {
	if links == nil {
		links = &tokenpb.DefaultLinks
	}
	return &TokenDocStore{
		DocStore: store,
		Links:    *links,
	}
}

func (s *TokenDocStore) AppTokenName(app uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppTokens)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{
		"App": app,
	})
}

func (s *TokenDocStore) InstallTokenName(app, install uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppTokens)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{
		"App":     app,
		"Install": install,
	})
}

func (s *TokenDocStore) GetAppTokenDoc(app uint64) (*tokenpb.AppToken, *docstore.CacheMeta, error) {
	docName, err := s.AppTokenName(app)
	if err != nil {
		return nil, nil, err
	}
	var token tokenpb.AppToken
	meta, err := s.GetDocument(docName, &token)
	return &token, meta, err
}

func (s *TokenDocStore) GetInstallTokenDoc(app, install uint64) (*tokenpb.InstallToken, *docstore.CacheMeta, error) {
	docName, err := s.InstallTokenName(app, install)
	if err != nil {
		return nil, nil, err
	}
	var token tokenpb.InstallToken
	meta, err := s.GetDocument(docName, &token)
	return &token, meta, err
}

func (s *TokenDocStore) PutAppTokenDoc(token *tokenpb.AppToken) (*docstore.CacheMeta, error) {
	docName, err := s.AppTokenName(token.App)
	if err != nil {
		return nil, err
	}
	return s.PutDocument(docName, token)
}

func (s *TokenDocStore) PutInstallTokenDoc(token *tokenpb.InstallToken) (*docstore.CacheMeta, error) {
	docName, err := s.InstallTokenName(token.App, token.Install)
	if err != nil {
		return nil, err
	}
	return s.PutDocument(docName, token)
}

func (s *TokenDocStore) DeleteAppTokenDoc(app uint64) (*docstore.CacheMeta, error) {
	docName, err := s.AppTokenName(app)
	if err != nil {
		return nil, err
	}
	return s.DeleteDocument(docName)
}

func (s *TokenDocStore) DeleteInstallTokenDoc(app, install uint64) (*docstore.CacheMeta, error) {
	docName, err := s.InstallTokenName(app, install)
	if err != nil {
		return nil, err
	}
	return s.DeleteDocument(docName)
}

type InstallTokenService struct {
	TokenDocStore
	AppTokenProvider
	InstallTokenProvider
}

func (s *InstallTokenService) installTokenIsValid(tokenDoc *tokenpb.InstallToken, logger kslog.KsLogger) bool {
	expiration, err := ptypes.Timestamp(tokenDoc.Expiration)
	if err != nil {
		logger.Errorf("Failed to parse fetched install token's expiration: %s", err)
		return false
	}
	now := time.Now()
	if now.After(expiration) {
		logger.Errorf("Fetched install token is expired")
		return false
	}
	return true
}

func (s *InstallTokenService) appTokenIsValid(tokenDoc *tokenpb.AppToken, logger kslog.KsLogger) bool {
	expiration, err := ptypes.Timestamp(tokenDoc.Expiration)
	if err != nil {
		logger.Errorf("Failed to parse fetched app token's expiration: %s", err)
		return false
	}
	now := time.Now()
	if now.After(expiration) {
		logger.Errorf("Fetched app token is expired")
		return false
	}
	return true
}

func (s *InstallTokenService) getNewAppToken(app uint64, logger kslog.KsLogger) (*tokenpb.AppToken, error) {
	token, expiration, err := s.AppTokenProvider(app)
	if err != nil {
		logger.Errorf("Failed to get new token for app %d: %s", app, err)
		return nil, err
	}
	pbexp, err := ptypes.TimestampProto(expiration)
	if err != nil {
		logger.Errorf("Failed to convert expiration %v of new app token to pb time", expiration, err)
		return nil, err
	}
	appTokenDoc := &tokenpb.AppToken{
		App:        app,
		Token:      token,
		Expiration: pbexp,
	}
	_, err = s.PutAppTokenDoc(appTokenDoc)
	if err != nil {
		logger.Errorf("Failed to put app token: %s", err)
	}
	return appTokenDoc, nil
}

func (s *InstallTokenService) GetInstallToken(req tokenpb.GetInstallTokenRequest, logger kslog.KsLogger) (*tokenpb.GetInstallTokenResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	installTokenDoc, _, err := s.GetInstallTokenDoc(req.App, req.Install)
	if err == nil && s.installTokenIsValid(installTokenDoc, logger) {
		resp := tokenpb.GetInstallTokenResponse{
			Token: installTokenDoc,
		}
		return &resp, nil
	}
	appTokenDoc, _, err := s.GetAppTokenDoc(req.App)
	if err != nil {
		logger.Errorf("Failed to get app %d token doc: %s", req.App, err)
		appTokenDoc = nil
	}
	if appTokenDoc != nil && !s.appTokenIsValid(appTokenDoc, logger) {
		appTokenDoc = nil
	}
	if appTokenDoc == nil {
		appTokenDoc, err = s.getNewAppToken(req.App, logger)
		if err != nil {
			return nil, err
		}
	}
	installToken, expiration, err := s.AppTokenProvider(req.App)
	if err != nil {
		logger.Errorf("Failed to get new token for app %d install %d: %s", req.App, req.Install, err)
		return nil, err
	}
	pbexp, err := ptypes.TimestampProto(expiration)
	if err != nil {
		logger.Errorf("Failed to convert expiration %v to pb: %s", expiration, err)
		return nil, err
	}
	installTokenDoc = &tokenpb.InstallToken{
		App:        req.App,
		Install:    req.Install,
		Token:      installToken,
		Expiration: pbexp,
	}
	_, err = s.PutInstallTokenDoc(installTokenDoc)
	if err != nil {
		logger.Errorf("Failed to put token for app %d install %d: %s", req.App, req.Install, err)
	}
	resp := tokenpb.GetInstallTokenResponse{
		Token: installTokenDoc,
	}
	return &resp, nil
}
