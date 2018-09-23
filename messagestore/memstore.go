package messagestore

type MemStore struct {
	Blobs map[string][]byte
}

func NewMemBlobStore() *MemStore {
	return &MemStore{
		Blobs: make(map[string][]byte),
	}
}

func NewMemMessageStore() *BlobMessageStore {
	return &BlobMessageStore{
		BlobStore: NewMemBlobStore(),
	}
}

var _ BlobStore = &MemStore{}

func (s *MemStore) GetBlob(name string) ([]byte, *CacheMeta, error) {
	storeBlob, found := s.Blobs[name]
	if !found {
		return nil, nil, NoSuchResource(name)
	}
	blobCopy := make([]byte, len(storeBlob))
	copy(blobCopy, storeBlob)
	return blobCopy, nil, nil
}

func (s *MemStore) PutBlob(name string, content []byte) (*CacheMeta, error) {
	storeCopy := make([]byte, len(content))
	copy(storeCopy, content)
	s.Blobs[name] = storeCopy
	return nil, nil
}

func (s *MemStore) DeleteBlob(name string) (*CacheMeta, error) {
	_, found := s.Blobs[name]
	if !found {
		return nil, NoSuchResource(name)
	}
	delete(s.Blobs, name)
	return nil, nil
}
