package docstore

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/keyservice"
	"github.com/aefalcon/go-github-keystore/keyutils"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/jtacoma/uritemplates"
)

type CacheMeta struct {
	CacheControl string
	ETag         string
	Expires      time.Time
	LastModified time.Time
}

type UnsupportedLocation appkeypb.Location

func (e *UnsupportedLocation) Error() string {
	return fmt.Sprintf("Ref type %T is not supported", (*appkeypb.Location)(e))
}

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

type DocStore interface {
	GetDocument(name string, pb proto.Message) (*CacheMeta, error)
	GetDocumentRaw(name string) ([]byte, *CacheMeta, error)
	PutDocument(name string, pb proto.Message) (*CacheMeta, error)
	PutDocumentRaw(name string, content []byte) (*CacheMeta, error)
	DeleteDocument(name string) (*CacheMeta, error)
}

type AppKeyStore struct {
	DocStore DocStore
	Links    appkeypb.Links
}

var _ keyservice.ManagerService = &AppKeyStore{}
var _ keyservice.SigningService = &AppKeyStore{}

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

func (s *AppKeyStore) GetAppIndexDoc() (*appkeypb.AppIndex, *CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, nil, err
	}
	var index appkeypb.AppIndex
	meta, err := s.DocStore.GetDocument(docName, &index)
	return &index, meta, err
}

func (s *AppKeyStore) PutAppIndexDoc(index *appkeypb.AppIndex) (*CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, err
	}
	return s.DocStore.PutDocument(docName, index)
}

func (s *AppKeyStore) DeleteAppIndexDoc() (*CacheMeta, error) {
	docName, err := s.AppIndexName()
	if err != nil {
		return nil, err
	}
	return s.DocStore.DeleteDocument(docName)
}

func (s *AppKeyStore) AppName(appId uint64) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.App)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId})
}

func (s *AppKeyStore) GetAppDoc(appId uint64) (*appkeypb.App, *CacheMeta, error) {
	docName, err := s.AppName(appId)
	if err != nil {
		return nil, nil, err
	}
	var app appkeypb.App
	meta, err := s.DocStore.GetDocument(docName, &app)
	return &app, meta, err
}

func (s *AppKeyStore) PutAppDoc(app *appkeypb.App) (*CacheMeta, error) {
	docName, err := s.AppName(app.Id)
	if err != nil {
		return nil, err
	}
	return s.DocStore.PutDocument(docName, app)
}

func (s *AppKeyStore) DeleteAppDoc(appId uint64) (*CacheMeta, error) {
	docName, err := s.AppName(appId)
	if err != nil {
		return nil, err
	}
	return s.DocStore.DeleteDocument(docName)
}

func (s *AppKeyStore) KeyName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.Key)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

func (s *AppKeyStore) GetKeyDoc(appId uint64, fingerprint string) ([]byte, *CacheMeta, error) {
	docName, err := s.KeyName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	return s.DocStore.GetDocumentRaw(docName)
}

func (s *AppKeyStore) PutKeyDoc(app uint64, fingerprint string, key []byte) (*CacheMeta, error) {
	docName, err := s.KeyName(app, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DocStore.PutDocumentRaw(docName, key)
}

func (s *AppKeyStore) DeleteKeyDoc(appId uint64, fingerprint string) (*CacheMeta, error) {
	docName, err := s.KeyName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DocStore.DeleteDocument(docName)
}

func (s *AppKeyStore) KeyMetaName(appId uint64, fingerprint string) (string, error) {
	uritmpl, err := uritemplates.Parse(s.Links.KeyMeta)
	if err != nil {
		return "", err
	}
	return uritmpl.Expand(map[string]interface{}{"AppId": appId, "Fingerprint": fingerprint})
}

func (s *AppKeyStore) GetKeyMetaDoc(appId uint64, fingerprint string) (*appkeypb.AppKeyMeta, *CacheMeta, error) {
	docName, err := s.KeyMetaName(appId, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	var appMeta appkeypb.AppKeyMeta
	cacheMeta, err := s.DocStore.GetDocument(docName, &appMeta)
	return &appMeta, cacheMeta, err
}

func (s *AppKeyStore) PutKeyMetaDoc(keyMeta *appkeypb.AppKeyMeta) (*CacheMeta, error) {
	docName, err := s.KeyMetaName(keyMeta.App, keyMeta.Fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DocStore.PutDocument(docName, keyMeta)
}

func (s *AppKeyStore) DeleteKeyMetaDoc(appId uint64, fingerprint string) (*CacheMeta, error) {
	docName, err := s.KeyMetaName(appId, fingerprint)
	if err != nil {
		return nil, err
	}
	return s.DocStore.DeleteDocument(docName)
}

func (s *AppKeyStore) AddApp(req *appkeypb.AddAppRequest, logger kslog.KsLogger) (*appkeypb.AddAppResponse, error) {
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

func (s *AppKeyStore) RemoveApp(req *appkeypb.RemoveAppRequest, logger kslog.KsLogger) (*appkeypb.RemoveAppResponse, error) {
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; !found {
		logger.Logf("Application %d not in index", req.App)
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
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	_, err = s.DeleteAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to remove app document for %d: %s", req.App, err)
		return nil, err
	}
	logger.Logf("Deleted application %d", req.App)
	removeKeysOk := true
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

func (s *AppKeyStore) GetApp(req *appkeypb.GetAppRequest, logger kslog.KsLogger) (*appkeypb.App, error) {
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	return app, err
}

func (s *AppKeyStore) ListApps(req *appkeypb.ListAppsRequest, logger kslog.KsLogger) (*appkeypb.AppIndex, error) {
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		logger.Logf("Failed to get application index: %s", err)
		return nil, err
	}
	return index, err
}

func (s *AppKeyStore) AddKey(req *appkeypb.AddKeyRequest, logger kslog.KsLogger) (*appkeypb.AddKeyResponse, error) {
	if len(req.Keys) == 0 {
		logger.Logf("No keys to add")
		return &appkeypb.AddKeyResponse{}, nil
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	if len(app.Keys) == 0 {
		app.Keys = make(map[string]*appkeypb.AppKeyIndexEntry)
		for _, key := range req.Keys {
			key.Meta.App = req.App
			app.Keys[key.Meta.Fingerprint] = &appkeypb.AppKeyIndexEntry{
				Meta: key.Meta,
			}
		}
	} else {
		for _, key := range req.Keys {
			if _, found := app.Keys[key.Meta.Fingerprint]; found {
				logger.Logf("App %d already has key %s", req.App, key.Meta.Fingerprint)
			}
			key.Meta.App = req.App
			app.Keys[key.Meta.Fingerprint] = &appkeypb.AppKeyIndexEntry{
				Meta: key.Meta,
			}
			_, err = s.PutKeyDoc(req.App, key.Meta.Fingerprint, key.Key)
			if err != nil {
				logger.Logf("Failed to put key document: %s", err)
				return nil, err
			}
			_, err = s.PutKeyMetaDoc(key.Meta)
			if err != nil {
				logger.Logf("Failed to put key metadata document: %s", err)
				return nil, err
			}
		}
	}
	_, err = s.PutAppDoc(app)
	if err != nil {
		logger.Logf("Failed to update application document: %s", err)
		return nil, err
	}
	return &appkeypb.AddKeyResponse{}, nil
}

func (s *AppKeyStore) RemoveKey(req *appkeypb.RemoveKeyRequest, logger kslog.KsLogger) (*appkeypb.RemoveKeyResponse, error) {
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

func (s *AppKeyStore) anyKeyFromApp(app *appkeypb.App, logger kslog.KsLogger) (*rsa.PrivateKey, string, error) {
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

func (s *AppKeyStore) Sign(req *appkeypb.SignRequest, logger kslog.KsLogger) (*appkeypb.SignedData, error) {
	if req.Algorithm != "RS256" {
		return nil, UnsupportedSignatureAlgo(req.Algorithm)
	}
	// sign with RSASSA-PKCS1-V1_5-SIGN using SHA-256
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get application document: %s", err)
		return nil, err
	}
	rsaKey, fingerprint, err := s.anyKeyFromApp(app, logger)
	if err != nil {
		logger.Logf("Failed to get key for app %d: %s", req.App, err)
		return nil, err
	}
	digest := sha256.Sum256(req.ProtectedData)
	sig, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		logger.Logf("Failed to sign protected data: %s", err)
		return nil, err
	}
	resp := appkeypb.SignedData{
		Signature:          sig,
		Algorithm:          req.Algorithm,
		SigningFingerprint: fingerprint,
	}
	return &resp, nil
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

func floatToTime(ts float64) time.Time {
	seconds := int64(ts)
	fraction := ts - float64(seconds)
	nanos := int64(fraction * 1e9)
	return time.Unix(seconds, nanos)
}

func timeToFloat(t time.Time) float64 {
	unixNano := t.UnixNano()
	floatT := float64(unixNano / int64(1e9))
	floatT += float64(unixNano%1e9) / float64(1e9)
	return floatT
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
	return floatToTime(numTime), true
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

func (s *AppKeyStore) SignJwt(req *appkeypb.SignJwtRequest, logger kslog.KsLogger) (*appkeypb.SignJwtResponse, error) {
	if req.Algorithm != "RS256" {
		return nil, UnsupportedSignatureAlgo(req.Algorithm)
	}
	now := time.Now().UTC()
	err := s.validateClaims(req, now)
	if err != nil {
		logger.Logf("Claims are invalid: %s", err)
		return nil, err
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Logf("Failed to get application document: %s", err)
		return nil, err
	}
	rsaKey, fingerprint, err := s.anyKeyFromApp(app, logger)
	if err != nil {
		logger.Logf("Failed to get key for app %d: %s", req.App, err)
		return nil, err
	}
	req.Claims.Fields["iss"] = &structpb.Value{
		Kind: &structpb.Value_NumberValue{
			NumberValue: timeToFloat(now),
		},
	}
	req.Claims.Fields["com.mobettersoftware.iss-kid"] = &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: fingerprint,
		},
	}
	jsonMarshaler := jsonpb.Marshaler{
		Indent: "",
	}
	claims, err := jsonMarshaler.MarshalToString(req.Claims)
	if err != nil {
		logger.Logf("Failed to marshal claims: %s", err)
		return nil, err
	}
	claimsBytes := []byte(claims)
	// sign with RSASSA-PKCS1-V1_5-SIGN using SHA-256
	digest := sha256.Sum256(claimsBytes)
	sig, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		logger.Logf("Failed to sign claims data: %s", err)
		return nil, err
	}
	resp := appkeypb.SignJwtResponse{
		Claims:    claimsBytes,
		Sig:       sig,
		Algorithm: req.Algorithm,
	}
	return &resp, nil
}
