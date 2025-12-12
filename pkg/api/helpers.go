package api

import (
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
)

type Client struct {
	identitypb.IdentityServiceClient
	client *gapi.Client
}

func NewClient(cfg gapi.ClientConfig) (*Client, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		IdentityServiceClient: identitypb.NewIdentityServiceClient(gapiClient.Conn),
		client:                gapiClient,
	}, nil
}

func (c *Client) Close() error {
	return c.client.Close()
}
