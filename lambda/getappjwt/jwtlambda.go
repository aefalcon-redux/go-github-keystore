package main

import (
	"bytes"
	"context"
	"log"
	"os"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/github-keystore-protobuf/go/locationpb"
	"github.com/aefalcon/go-github-keystore/appkeystore"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/messagestore"
	"github.com/aefalcon/go-github-keystore/s3store"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang/protobuf/jsonpb"
)

type LambdaSignJwtRequest struct {
	appkeypb.SignJwtRequest
}

func (r *LambdaSignJwtRequest) UnmarshalJSON(data []byte) error {
	dataReader := bytes.NewReader(data)
	return jsonpb.Unmarshal(dataReader, &r.SignJwtRequest)
}

type LambdaSignJwtResponse struct {
	appkeypb.SignJwtResponse
}

func (r *LambdaSignJwtResponse) MarshalJSON() ([]byte, error) {
	marshaler := jsonpb.Marshaler{}
	buffer := bytes.NewBuffer(nil)
	err := marshaler.Marshal(buffer, &r.SignJwtResponse)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func HandleRequest(service *appkeystore.AppKeyService, ctx context.Context, req *LambdaSignJwtRequest) (*LambdaSignJwtResponse, error) {
	logger := kslog.DefaultLogger{}
	resp, err := service.SignJwt(&req.SignJwtRequest, logger)
	if err != nil {
		return nil, err
	}
	reply := LambdaSignJwtResponse{*resp}
	return &reply, nil
}

func main() {
	storeBucket := os.Getenv("STORE_BUCKET")
	storePrefix := os.Getenv("STORE_PREFIX")
	storeRegion := os.Getenv("STORE_REGION")
	location := locationpb.Location{
		Location: &locationpb.Location_S3{
			S3: &locationpb.S3Ref{
				Bucket: storeBucket,
				Key:    storePrefix,
				Region: storeRegion,
			},
		},
	}
	blobStore, err := s3store.NewS3BlobStore(&location)
	if err != nil {
		log.Fatalf("Failed to create store: %s", err)
	}
	docStore := messagestore.BlobMessageStore{
		BlobStore: blobStore,
	}
	keyService := appkeystore.NewAppKeyService(&docStore, nil)
	handleFunc := func(ctx context.Context, req *LambdaSignJwtRequest) (*LambdaSignJwtResponse, error) {
		return HandleRequest(keyService, ctx, req)
	}
	lambda.Start(handleFunc)
}
