package api

import (
	"context"
	"encoding/json"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/k8shell-io/identity/pkg/api/idppb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IdentityClient struct {
	identitypb.IdentityServiceClient
	client *gapi.Client
}

func NewIdentityClient(cfg gapi.ClientConfig) (*IdentityClient, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &IdentityClient{
		IdentityServiceClient: identitypb.NewIdentityServiceClient(gapiClient.Conn),
		client:                gapiClient,
	}, nil
}

func (c *IdentityClient) Close() error {
	return c.client.Close()
}

type IdpClient struct {
	Name         string
	Capabilities []string
	UserMaxAge   uint32
	Address      string
	idppb.IdentityProviderServiceClient
	client *gapi.Client
}

func NewIdpClient(cfg gapi.ClientConfig) (*IdpClient, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	client := &IdpClient{
		IdentityProviderServiceClient: idppb.NewIdentityProviderServiceClient(gapiClient.Conn),
		client:                        gapiClient,
	}
	info, err := client.ProviderInfo(context.Background(), &idppb.ProviderInfoRequest{})
	if err != nil {
		gapiClient.Close()
		return nil, err
	}
	client.Name = info.Name
	client.Capabilities = info.Capabilities
	client.UserMaxAge = info.UserMaxAge
	client.Address = info.Address
	return client, nil

}

func (c *IdpClient) Close() error {
	return c.client.Close()
}

func BlueprintProtoToCustomBlueprint(bp *typespb.Blueprint) (*models.CustomBlueprint, error) {
	if bp == nil {
		return nil, nil
	}
	var customBlueprint models.CustomBlueprint
	err := json.Unmarshal([]byte(bp.BlueprintJson), &customBlueprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to parse custom blueprint JSON: %v", err)
	}
	return &customBlueprint, nil
}
