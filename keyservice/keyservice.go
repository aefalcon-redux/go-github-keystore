package keyservice

import (
	"github.com/aefalcon-redux/github-keystore-protobuf/go/appkeypb"
)

type ManagerService interface {
	AddApp(*appkeypb.AddAppRequest) (*appkeypb.AddAppResponse, error)
	RemoveApp(*appkeypb.RemoveAppRequest) (*appkeypb.RemoveAppResponse, error)
	GetApp(*appkeypb.GetAppRequest) (*appkeypb.App, error)
	ListAps(*appkeypb.ListAppsRequest) (*appkeypb.AppIndex, error)
	AddKey(*appkeypb.AddKeyRequest) (*appkeypb.AddKeyResponse, error)
	RemoveKey(*appkeypb.RemoveKeyRequest) (*appkeypb.RemoveKeyResponse, error)
}

type SigningService interface {
	Sign(*appkeypb.SignRequest) (*appkeypb.SignedData, error)
}
