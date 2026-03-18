package server

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/gapi"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/identity/internal/providers/file"
)

// KubernetesConfig contains configuration for Kubernetes secret management
// and distributed leader election.
type KubernetesConfig struct {
	// Enabled toggles Kubernetes secret management. When false, no secrets are
	// written and no leader election is performed.
	Enabled bool `yaml:"enabled"`

	// Namespace is the Kubernetes namespace where user token secrets are created.
	Namespace string `yaml:"namespace"`

	// SecretPrefix is the prefix for user token secret names.
	// The full name is <SecretPrefix><username>. Defaults to "identity-token-".
	SecretPrefix string `yaml:"secretPrefix"`

	// LeaseName is the name of the Lease object used for leader election when
	// the database is not configured. Defaults to "identity-token-refresh".
	LeaseName string `yaml:"leaseName"`

	// LeaseNamespace is the namespace for the leader election Lease. Defaults
	// to Namespace when empty.
	LeaseNamespace string `yaml:"leaseNamespace"`

	// KubeconfigPath is the path to a kubeconfig file. When empty the
	// in-cluster service-account configuration is used, falling back to
	// $KUBECONFIG / ~/.kube/config for local development.
	KubeconfigPath string `yaml:"kubeconfigPath"`

	// RefreshInterval is how often the background loop checks for near-expiry
	// tokens. Defaults to 15 minutes.
	RefreshInterval time.Duration `yaml:"refreshInterval"`

	// RefreshLookahead is the remaining-lifetime threshold below which a token
	// is considered due for renewal. Defaults to 20 minutes.
	RefreshLookahead time.Duration `yaml:"refreshLookahead"`
}

// Config contains server configuration loaded from YAML.
type Config struct {
	// GrpcConfig configures the gRPC server.
	GrpcConfig gapi.ServerConfig `yaml:"grpc"`

	// Nats configures the NATS client.
	Nats natsc.NATSClientConfig `yaml:"nats"`

	// DB configures the database connection.
	DB db.DBConfig `yaml:"db"`

	// LocalProviders configures local file-based identity providers.
	LocalProviders file.FileUserProviderConfig `yaml:"localProviders"`

	// RemoteProviders configures remote identity provider clients.
	RemoteProviders []gapi.ClientConfig `yaml:"remoteProviders"`

	// JWTIssuer configures JWT token issuance.
	JWTIssuer authz.JWTIssuerConfig `yaml:"jwtIssuer"`

	// JWTVerifier configures JWT token verification for GetUserByAccessToken.
	// For hs256 the SecretKey is inherited from JWTIssuer automatically.
	// For rs256/es256 set PublicKeyFile to the PEM-encoded public key path.
	JWTVerifier authz.JWTVerifierConfig `yaml:"jwtVerifier"`

	// Kubernetes configures Kubernetes secret management and distributed
	// leader election for the token refresh loop.
	Kubernetes KubernetesConfig `yaml:"kubernetes"`

	// configDir is the directory containing the loaded configuration file.
	configDir string
}

// LoadConfig loads server configuration from configFile.
func LoadConfig(configFile string) (*Config, error) {
	var cfg Config
	err := config.LoadConfig(configFile, &cfg)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	absPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("resolve config file path: %w", err)
	}
	cfg.configDir = filepath.Dir(absPath)

	return &cfg, nil
}
