package docstore

import (
	"fmt"
	"log"
	"time"

	"github.com/aefalcon-redux/github-keystore-protobuf/go/appkeypb"
	"github.com/golang/protobuf/proto"
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

func (s *AppKeyStore) AddApp(req *appkeypb.AddAppRequest, logger *log.Logger) (*appkeypb.AddAppResponse, error) {
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

func (s *AppKeyStore) RemoveApp(req *appkeypb.RemoveAppRequest, logger *log.Logger) (*appkeypb.RemoveAppResponse, error) {
	index, _, err := s.GetAppIndexDoc()
	if err != nil {
		return nil, err
	}
	if _, found := index.AppRefs[req.App]; !found {
		logger.Printf("Application %d not in index", req.App)
	} else {
		delete(index.AppRefs, req.App)
		_, err = s.PutAppIndexDoc(index)
		if err != nil {
			logger.Fatalf("Failed to put updated application index")
			return nil, err
		}
		logger.Printf("Application %d removed from index", req.App)
	}
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Printf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	_, err = s.DeleteAppDoc(req.App)
	if err != nil {
		logger.Printf("Failed to remove app document for %d: %s", req.App, err)
		return nil, err
	}
	logger.Printf("Deleted application %d", req.App)
	removeKeysOk := true
	for _, key := range app.Keys {
		_, err = s.DeleteKeyMetaDoc(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Printf("Failed to remove key %s metadata", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Printf("Deleted key %s metadata", key.Meta.Fingerprint)
		}
		_, err = s.DeleteKeyDoc(req.App, key.Meta.Fingerprint)
		if err != nil {
			logger.Printf("Failed to remove key %s", key.Meta.Fingerprint)
			removeKeysOk = false
		} else {
			logger.Printf("Deleted key %s", key.Meta.Fingerprint)
		}
	}
	if !removeKeysOk {
		return nil, fmt.Errorf("Failed to remove keys")
	} else {
		logger.Printf("Deleted all keys")
	}
	return &appkeypb.RemoveAppResponse{}, nil
}

func (s *AppKeyStore) GetApp(req *appkeypb.GetAppRequest, logger *log.Logger) (*appkeypb.App, error) {
	app, _, err := s.GetAppDoc(req.App)
	if err != nil {
		logger.Printf("Failed to get app %d: %s", req.App, err)
		return nil, err
	}
	return app, err
}