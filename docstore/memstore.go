package docstore

type MemStore struct {
	Docs map[string][]byte
}

func NewMemBlobStore() BlobStore {
	return &MemStore{
		Docs: make(map[string][]byte),
	}
}

var _ BlobStore = &MemStore{}

func (s *MemStore) GetDocumentRaw(name string) ([]byte, *CacheMeta, error) {
	storeDoc, found := s.Docs[name]
	if !found {
		return nil, nil, NoSuchResource(name)
	}
	returnDoc := make([]byte, len(storeDoc))
	copy(returnDoc, storeDoc)
	return returnDoc, nil, nil
}

func (s *MemStore) PutDocumentRaw(name string, content []byte) (*CacheMeta, error) {
	storeCopy := make([]byte, len(content))
	copy(storeCopy, content)
	s.Docs[name] = storeCopy
	return nil, nil
}

func (s *MemStore) DeleteDocument(name string) (*CacheMeta, error) {
	_, found := s.Docs[name]
	if !found {
		return nil, NoSuchResource(name)
	}
	delete(s.Docs, name)
	return nil, nil
}
