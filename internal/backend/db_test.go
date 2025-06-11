package backend_test

import (
	"testing"

	"github.com/k8shell-io/identity/internal/backend"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	// PostgreSQL test configuration
	DBUSER     = "testuser"
	DBPASSWORD = "testpass"
	DBNAME     = "testdb"
	PORT       = 5433
)

// createDBResource sets up a PostgreSQL Docker container for testing
func createDBResource() (*dockertest.Pool, *dockertest.Resource, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, nil, err
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "15",
		Env: []string{
			"POSTGRES_USER=" + DBUSER,
			"POSTGRES_PASSWORD=" + DBPASSWORD,
			"POSTGRES_DB=" + DBNAME,
		},
		ExposedPorts: []string{"5432/tcp"},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
		config.PortBindings = map[docker.Port][]docker.PortBinding{
			"5432/tcp": {
				{
					HostIP:   "0.0.0.0",
					HostPort: "5433",
				},
			},
		}
	})
	if err != nil {
		return nil, nil, err
	}
	return pool, resource, nil
}

func getDB(pool *dockertest.Pool, resource *dockertest.Resource) (*backend.DB, error) {
	cfg := backend.DBConfig{
		Username: DBUSER,
		Password: DBPASSWORD,
		Database: DBNAME,
		Hostname: "localhost",
		Port:     PORT,
	}
	cfg.SetDefaults()

	var db *backend.DB
	err := pool.Retry(func() error {
		var err error
		db, err = backend.NewDB(cfg)
		return err
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func TestNewDB_Success(t *testing.T) {
	pool, resource, err := createDBResource()
	if err != nil {
		t.Fatalf("Could not create Docker resource: %s", err)
	}

	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	db, err := getDB(pool, resource)
	if err != nil {
		t.Fatalf("Could not create DB: %s", err)
	}
	defer db.Close()

	if db == nil {
		t.Fatal("Expected non-nil DB")
	}
}
