package appkeystore

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/keyservice"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/messagestore"
	"github.com/aefalcon/go-github-keystore/timeutils"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/jtacoma/uritemplates"
)

type AppExists uint64

func (e AppExists) Error() string {
	return fmt.Sprintf("app %d already exists", uint64(e))
}

type UnallowedAppId uint64

func (e UnallowedAppId) Error() string {
	return fmt.Sprintf("app id %d is not allowed", uint64(e))
}

type UnsupportedSignatureAlgo string

func (e UnsupportedSignatureAlgo) Error() string {
	return fmt.Sprintf("unsupported algorithm %s", string(e))
}

type NoKeyForApp uint64

func (e NoKeyForApp) Error() string {
	return fmt.Sprintf("No key for app %d", uint64(e))
}

type InvalidClaims string

func (e InvalidClaims) Error() string {
	return string(e)
}

type FingerprintMismatch struct {
	Given   string
	Derived string
}

func (e *FingerprintMismatch) Error() string {
	return fmt.Sprintf("derived fingerprint %s for key with stated fingerprint %s", e.Derived, e.Given)
}

type StoreBackend interface {
	messagestore.BlobStore
	messagestore.MessageStore
}

type AppKeyStore struct {
	StoreBackend
	Links appkeypb.Links
}

func NewAppKeyStore(backend StoreBackend, links *appkeypb.Links) *AppKeyStore {
	if links == nil {
		links = &appkeypb.DefaultLinks
	}
	return &AppKeyStore{
		StoreBackend: backend,
		Links:        *links,
	}
}

func (s *AppKeyStore) InitDb(logger kslog.KsLogger) error {
	var index appkeypb.AppIndex
	_, err := s.PutAppIndexDoc(&index)
	if err != nil {
		logger.Error("Failed to put application index")
	}
	return err
}

func (s *AppKeyStore) AppIndexName() (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.AppIndex)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{})
}

func (s *AppKeyStore) GetAppIndexDoc() (*appkeypb.AppIndex, *messagestore.CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, nil, err
	}
	var index appkeypb.AppIndex
	meta, err := s.GetMessage(docName, &index)
	return &index, meta, err
}

func (s *AppKeyStore) PutAppIndexDoc(index *appkeypb.AppIndex) (*messagestore.CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, err
	}
	return s.PutMessage(docName, index)
}

func (s *AppKeyStore) DeleteAppIndexDoc() (*messagestore.CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(docName)
}

func (s *AppKeyStore) AppName(appId uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.App)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId})
}

func (s *AppKeyStore) GetAppDoc(appId uint64) (*appkeypb.App, *messagestore.CacheMeta, error) {
	docName, err := s.AppName(appId)
	if err != nil {
		return nil, nil, err
	}
	var app appkeypb.App
	meta, err := s.GetMessage(docName, &app)
	return &app, meta, err
}

func (s *AppKeyStore) PutAppDoc(app *appkeypb.App) (*messagestore.CacheMeta, error) {
	docName, err := s.AppName(app.Id)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(docName, app)
}

func (s *AppKeyStore) DeleteAppDoc(appId uint64) (*messagestore.CacheMeta, error) {
	docName, err := s.AppName(appId)
	if err != nil {
		return nil, err
	}
	return s.DeleteMessage(docName)
}

func (s *AppKeyStore) KeyName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.Key)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

func (s *AppKeyStore) GetKeyDoc(appId uint64, fingerprint string) ([]byte, *messagestore.CacheMeta, error) {
	docName, err := s.KeyName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	return s.GetBlob(docName)
}

func (s *AppKeyStore) PutKeyDoc(app uint64, fingerprint string, key []byte) (*messagestore.CacheMeta, error) {
	docName, err := s.KeyName(app, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.PutBlob(docName, key)
}

func (s *AppKeyStore) DeleteKeyDoc(appId uint64, fingerprint string) (*messagestore.CacheMeta, error) {
	docName, err := s.KeyName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DeleteBlob(docName)
}

func (s *AppKeyStore) KeyMetaName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.KeyMeta)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

func (s *AppKeyStore) GetKeyMetaDoc(appId uint64, fingerprint string) (*appkeypb.AppKeyMeta, *messagestore.CacheMeta, error) {
	docName, err := s.KeyMetaName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	var appMeta appkeypb.AppKeyMeta
	cacheMeta, err := s.GetMessage(docName, &appMeta)
	return &appMeta, cacheMeta, err
}

func (s *AppKeyStore) PutKeyMetaDoc(keyMeta *appkeypb.AppKeyMeta) (*messagestore.CacheMeta, error) {
	docName, err := s.KeyMetaName(keyMeta.App, keyMeta.Fingerprint)
	if err != nil {
		return nil, err
	}
	return s.PutMessage(docName, keyMeta)
}

func (s *AppKeyStore) DeleteKeyMetaDoc(appId uint64, fingerprint string) (*messagestore.CacheMeta, error) {
	docName, err := s.KeyMetaName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DeleteBlob(docName)
}

type AppKeyService struct {
	*AppKeyStore
}

func NewAppKeyService(backend StoreBackend, links *appkeypb.Links) *AppKeyService {
	return &AppKeyService{
		AppKeyStore: NewAppKeyStore(backend, links),
	}
}

var _ keyservice.ManagerService = &AppKeyService{}
var _ keyservice.SigningService = &AppKeyService{}

func (s *AppKeyService) AddApp(req *appkeypb.AddAppRequest, logger kslog.KsLogger) (*appkeypb.AddAppResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; found {
		return nil, AppExists(req.App)
	}
	if index.AppRefs == nil {
		index.AppRefs = make(map[uint64]*appkeypb.AppIndexEntry)
	}
	index.AppRefs[req.App] = &appkeypb.AppIndexEntry{
		Id: req.App,
	}
	app := appkeypb.App{
		Id: req.App,
	}
	if len(req.Keys) > 0 {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry, len(req.Keys))
		for _, reqKey := range req.Keys {
			rsaKey, err := keyutils.ParsePrivateKey(reqKey.Key)
			if err != nil {
				return nil, err
			}
			fingerprint, err := keyutils.KeyFingerprint(rsaKey)
			if err != nil {
				return nil, err
			}
			if reqKey.Meta.Fingerprint != fingerprint {
				return nil, &FingerprintMismatch{
					Given:   reqKey.Meta.Fingerprint,
					Derived: fingerprint,
				}
			}
			app.Keys[fingerprint] = &appkeypb.AppKeyIndexEntry{
				Meta: reqKey.Meta,
			}
		}
		for _, reqKey := range req.Keys {
			_, err = s.PutKeyDoc(req.App, reqKey.Meta.Fingerprint, reqKey.Key)
			if err != nil {
				logger.Logf("Failed to put key document: %s", err)
				return nil, err
			}
			_, err = s.PutKeyMetaDoc(reqKey.Meta)
			if err != nil {
				logger.Logf("Failed to put key metadata document: %s", err)
				return nil, err
			}
		}
	}
	_, err = s.PutAppDoc(&app)
	if err != nil {
		return nil, err
	}
	_, err = s.PutAppIndexDoc(index)
	if err != nil {
		return nil, err
	}
	return &appkeypb.AddAppResponse{}, nil
}

func (s *AppKeyService) RemoveApp(req *appkeypb.RemoveAppRequest, logger kslog.KsLogger) (*appkeypb.RemoveAppResponse, error) {
	if req.App == 0 {
		logger.Errorf("Attempted to add app %d", req.App)
		return nil, UnallowedAppId(req.App)
	}
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		logger.Errorf("failed to get app index: %s", err)
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; !found {
		logger.Errorf("Application %d not in index", req.App)
	} else {
		delete(index.AppRefs, req.App)
		_, err = s.PutAppIndexDoc(index)
		if err != nil {
			logger.Error("Failed to put updated application index")
			return nil, err
		}
		logger.Logf("Application %d removed from index", req.App)
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Errorf("Failed to get app %d: %s", req.App, err)
		return nil, err
	} else {
		logger.Logf("Fetched app document for %d", req.App)
	}
	_, err = s.DeleteAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to remove app document for %d: %s", req.App, err)
		return nil, err
	}
	logger.Logf("Deleted application %d", req.App)
	removeKeysOk := true
	if len(app.Keys) == 0 {
		logger.Logf("no keys to delete")
		return &appkeypb.RemoveAppResponse{}, nil
	}
	for _, key := range app.Keys {
		_, err = s.DeleteKeyMetaDoc(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to remove key %s metadata", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Logf("Deleted key %s metadata", key.Meta.Fingerprint)
		}
		_, err = s.DeleteKeyDoc(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to remove key %s", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Logf("Deleted key %s", key.Meta.Fingerprint)
		}
	}
	if !removeKeysOk {
		return nil, fmt.Errorf("Failed to remove keys")
	} else {
		logger.Logf("Deleted all keys")
	}
	return &appkeypb.RemoveAppResponse{}, nil
}

func (s *AppKeyService) GetApp(req *appkeypb.GetAppRequest, logger kslog.KsLogger) (*appkeypb.App, error) {
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	return app, err
}

func (s *AppKeyService) ListApps(req *appkeypb.ListAppsRequest, logger kslog.KsLogger) (*appkeypb.AppIndex, error) {
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		logger.Logf("Failed to get application index: %s", err)
		return nil, err
	}
	return index, err
}

func (s *AppKeyService) AddKey(req *appkeypb.AddKeyRequest, logger kslog.KsLogger) (*appkeypb.AddKeyResponse, error) {
	if len(req.Keys) == 0 {
		logger.Logf("No keys to add")
		return &appkeypb.AddKeyResponse{}, nil
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	logger.Logf("Adding %d keys", len(req.Keys))
	if len(app.Keys) == 0 {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry)
	}
	keysToAdd := make([]*appkeypb.AppKey, 0, len(req.Keys))
	for _, key := range req.Keys {
		if _, found := app.Keys[key.Meta.Fingerprint]; found {
			logger.Logf("App %d already has key %s", req.App, key.Meta.Fingerprint)
			continue
		}
		key.Meta.App = req.App
		app.Keys[key.Meta.Fingerprint] = &appkeypb.AppKeyIndexEntry{
			Meta: key.Meta,
		}
		keysToAdd = append(keysToAdd, key)
	}
	for _, key := range keysToAdd {
		logger.Logf("Adding key %s", key.Meta.Fingerprint)
		_, err = s.PutKeyDoc(req.App, key.Meta.Fingerprint, key.Key)
		if err != nil {
			logger.Logf("Failed to put key document: %s", err)
			return nil, err
		}
		logger.Logf("Added key %s", key.Meta.Fingerprint)
		_, err = s.PutKeyMetaDoc(key.Meta)
		if err != nil {
			logger.Logf("Failed to put key metadata document: %s", err)
			return nil, err
		}
		logger.Logf("Added key metadata for %s", key.Meta.Fingerprint)
	}
	_, err = s.PutAppDoc(app)
	if err != nil {
		logger.Logf("Failed to update application document: %s", err)
		return nil, err
	}
	return &appkeypb.AddKeyResponse{}, nil
}

func (s *AppKeyService) RemoveKey(req *appkeypb.RemoveKeyRequest, logger kslog.KsLogger) (*appkeypb.RemoveKeyResponse, error) {
	for _, fingerprint := range req.Fingerprints {
		_, err := s.DeleteKeyDoc(req.App, fingerprint)
		if err != nil {
			logger.Logf("Failed delete key %s: %s", fingerprint, err)
		}
		_, err = s.DeleteKeyMetaDoc(req.App, fingerprint)
		if err != nil {
			logger.Logf("Failed delete key %s metadata: %s", fingerprint, err)
		}
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	for _, fingerprint := range req.Fingerprints {
		if _, found := app.Keys[fingerprint]; !found {
			logger.Errorf("App %d does not have  key %s", req.App, fingerprint)
		}
		delete(app.Keys, fingerprint)
	}
	_, err = s.PutAppDoc(app)
	if err != nil {
		logger.Errorf("Failed to update application document: %s", err)
	}
	return &appkeypb.RemoveKeyResponse{}, nil
}

func (s *AppKeyService) anyKeyFromApp(app *appkeypb.App, logger kslog.KsLogger) (*rsa.PrivateKey, string, error) {
	var key []byte
	var fingerprint string
	for _, keyEntry := range app.Keys {
		if keyEntry.Meta.Disabled {
			continue
		}
		var err error
		key, _, err = s.GetKeyDoc(app.Id, keyEntry.Meta.Fingerprint)
		if err != nil {
			logger.Logf("Failed to get key %s for app %d", keyEntry.Meta.Fingerprint, app.Id)
		}
		fingerprint = keyEntry.Meta.Fingerprint
		break
	}
	if key == nil {
		logger.Logf("Did not find a key for app %d", app.Id)
		return nil, "", NoKeyForApp(app.Id)
	}
	rsaKey, err := keyutils.ParsePrivateKey(key)
	if err != nil {
		logger.Logf("Failed to parse private key %s: %s", fingerprint, err)
		return nil, "", err
	}
	return rsaKey, fingerprint, nil
}

func validateIssClaim(app uint64, iss string) error {
	issAsInt, err := strconv.ParseUint(iss, 10, 64)
	if err != nil {
		return InvalidClaims(fmt.Sprintf("Could not parse `iss` to int: %s", err))
	}
	if app != issAsInt {
		return InvalidClaims(fmt.Sprintf("Application Id in request (%d) does not match claim `iss` (%d)", app, issAsInt))
	}
	return nil
}

func validateExpNbfClaims(exp, nbf, now time.Time) error {
	if !exp.After(now) {
		return InvalidClaims("`exp` indicates claims are already expired")
	}
	if !nbf.IsZero() {
		if !exp.After(nbf) {
			return InvalidClaims("`exp` must be greater than `nbf`")
		}
		if nbf.Before(now) && now.Sub(nbf) > time.Second*5 {
			return InvalidClaims("`nbf` is more than 5 seconds in the past")
		}
	}
	return nil
}

func pbValToStr(v *structpb.Value) (string, bool) {
	stringVal, ok := v.Kind.(*structpb.Value_StringValue)
	if !ok {
		return "", false
	}
	return stringVal.StringValue, true
}

func pbValToNum(v *structpb.Value) (float64, bool) {
	numVal, ok := v.Kind.(*structpb.Value_NumberValue)
	if !ok {
		return 0.0, false
	}
	return numVal.NumberValue, true
}

func pbValToTime(v *structpb.Value) (time.Time, bool) {
	numTime, ok := pbValToNum(v)
	if !ok {
		return time.Time{}, false
	}
	return timeutils.FloatToTime(numTime), true
}

func (s *AppKeyStore) validateClaims(req *appkeypb.SignJwtRequest, now time.Time) error {
	issVal := req.Claims.Fields["iss"]
	if issVal == nil {
		return InvalidClaims("Missing claim `iss`")
	}
	iss, ok := pbValToStr(issVal)
	if !ok {
		return InvalidClaims("`iss` must be string")
	}
	if err := validateIssClaim(req.App, iss); err == nil {
		return err
	}
	expVal := req.Claims.Fields["exp"]
	if expVal == nil {
		return InvalidClaims("Missing claim `exp`")
	}
	exp, ok := pbValToTime(expVal)
	if !ok {
		return InvalidClaims("`exp` must be numeric")
	}
	nbfVal, ok := req.Claims.Fields["nbf"]
	var nbf time.Time
	if nbfVal != nil {
		nbf, ok = pbValToTime(nbfVal)
		if !ok {
			return InvalidClaims("`nbf` must be numeric")
		}
	}
	if err := validateExpNbfClaims(exp, nbf, now); err != nil {
		return err
	}
	iatVal := req.Claims.Fields["iat"]
	if iatVal != nil {
		return InvalidClaims("Do not include `iat` in claims")
	}
	return nil
}

func (s *AppKeyService) SignJwt(req *appkeypb.SignJwtRequest, logger kslog.KsLogger) (*appkeypb.SignJwtResponse, error) {
	if req.Algorithm != "RS256" {
		return nil, UnsupportedSignatureAlgo(req.Algorithm)
	}
	now := time.Now().UTC()
	err := s.validateClaims(req, now)
	if err != nil {
		logger.Errorf("Claims are invalid: %s", err)
		return nil, err
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Errorf("Failed to get application document: %s", err)
		return nil, err
	}
	rsaKey, fingerprint, err := s.anyKeyFromApp(app, logger)
	if err != nil {
		logger.Errorf("Failed to get key for app %d: %s", req.App, err)
		return nil, err
	}
	req.Claims.Fields["iat"] = &structpb.Value{
		Kind: &structpb.Value_NumberValue{
			NumberValue: float64(int64(timeutils.TimeToFloat(now))),
		},
	}
	req.Claims.Fields["com.mobettersoftware.auth-kid"] = &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: fingerprint,
		},
	}
	jsonMarshaler := jsonpb.Marshaler{
		Indent: "",
	}
	claims, err := jsonMarshaler.MarshalToString(req.Claims)
	if err != nil {
		logger.Errorf("Failed to marshal claims: %s", err)
		return nil, err
	}
	claims64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(claims)))
	base64.RawURLEncoding.Encode(claims64, []byte(claims))
	header, err := json.Marshal(map[string]interface{}{
		"typ": "JWT",
		"alg": req.Algorithm,
	})
	if err != nil {
		logger.Errorf("Failed to marshal header: %s", err)
	}
	header64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(header)))
	base64.RawURLEncoding.Encode(header64, []byte(header))
	secureData := make([]byte, len(claims64)+len(header64)+1)
	copy(secureData, header64)
	secureData[len(header64)] = '.'
	copy(secureData[len(header64)+1:], claims64)
	// sign with RSASSA-PKCS1-V1_5-SIGN using SHA-256
	digest := sha256.Sum256(secureData)
	sig, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		logger.Logf("Failed to sign claims data: %s", err)
		return nil, err
	}
	token := make([]byte, len(secureData)+1+base64.RawURLEncoding.EncodedLen(len(sig)))
	copy(token, secureData)
	token[len(secureData)] = '.'
	base64.RawURLEncoding.Encode(token[len(secureData)+1:], sig[:])
	resp := appkeypb.SignJwtResponse{
		Jwt: string(token),
	}
	return &resp, nil
}
