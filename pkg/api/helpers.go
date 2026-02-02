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

type IdpClient interface {
	Name() string
	Capabilities() []string
	UserMaxAge() uint32
	Address() string
	Close() error
	idppb.IdentityProviderServiceClient
}

type idpClient struct {
	idppb.IdentityProviderServiceClient
	client *gapi.Client

	name         string
	capabilities []string
	userMaxAge   uint32
	address      string
}

func (c *idpClient) Close() error { return c.client.Close() }

func (c *idpClient) Name() string           { return c.name }
func (c *idpClient) Capabilities() []string { return c.capabilities }
func (c *idpClient) UserMaxAge() uint32     { return c.userMaxAge }
func (c *idpClient) Address() string        { return c.address }

func NewIdpClient(cfg gapi.ClientConfig) (IdpClient, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	c := &idpClient{
		IdentityProviderServiceClient: idppb.NewIdentityProviderServiceClient(gapiClient.Conn),
		client:                        gapiClient,
	}

	info, err := c.ProviderInfo(context.Background(), &idppb.ProviderInfoRequest{})
	if err != nil {
		_ = gapiClient.Close()
		return nil, err
	}

	c.name = info.Name
	c.capabilities = info.Capabilities
	c.userMaxAge = info.UserMaxAge
	c.address = info.Address

	return c, nil
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
