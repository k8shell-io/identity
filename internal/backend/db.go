package backend

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/k8shell-io/common/logger"
	"github.com/rs/zerolog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type DBConfig struct {
	Username          string        `yaml:"username"`
	Password          string        `yaml:"password"`
	Database          string        `yaml:"database"`
	Hostname          string        `yaml:"hostname"`
	Port              int           `yaml:"port"`
	MaxConns          int32         `yaml:"maxConns"`
	MinConns          int32         `yaml:"minConns"`
	MaxConnIdleTime   time.Duration `yaml:"maxConnIdleTime"`
	MaxConnLifetime   time.Duration `yaml:"maxConnLifetime"`
	HealthCheckPeriod time.Duration `yaml:"healthCheckPeriod"`
}

type DB struct {
	config DBConfig
	pool   *pgxpool.Pool
	log    *zerolog.Logger
}

const (
	MigrationDir     = "db/migrations"
	DefaultListLimit = 50
	MaxListLimit     = 100
)

func runDBMigrations(connString string, migrarionBaseDir string) error {
	m, err := migrate.New(
		fmt.Sprintf("file:/%s/%s", migrarionBaseDir, MigrationDir),
		connString,
	)
	if err != nil {
		return fmt.Errorf("init migrate: %w", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrate: %w", err)
	}
	return nil
}

func (c *DBConfig) SetDefaults() {
	if c.Port == 0 {
		c.Port = 5432
	}
	if c.MaxConns == 0 {
		c.MaxConns = 10
	}
	if c.MinConns == 0 {
		c.MinConns = 1
	}
	if c.MaxConnIdleTime == 0 {
		c.MaxConnIdleTime = 5 * time.Minute
	}
	if c.MaxConnLifetime == 0 {
		c.MaxConnLifetime = time.Hour
	}
	if c.HealthCheckPeriod == 0 {
		c.HealthCheckPeriod = 30 * time.Second
	}
}

func (c *DBConfig) ConnString() string {
	q := url.Values{}
	q.Add("sslmode", "disable") // or "require"

	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?%s",
		url.QueryEscape(c.Username),
		url.QueryEscape(c.Password),
		url.QueryEscape(c.Hostname),
		c.Port,
		url.QueryEscape(c.Database),
		q.Encode(),
	)
}

func NewDB(config DBConfig, migrationBaseDir string) (*DB, error) {
	log := log.NewLogger("db")
	if config.Username == "" || config.Password == "" || config.Database == "" || config.Hostname == "" {
		return nil, fmt.Errorf("database configuration is incomplete: username, password, database, and hostname are required")
	}
	config.SetDefaults()
	connString := config.ConnString()
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}

	poolConfig.MaxConns = config.MaxConns
	poolConfig.MinConns = config.MinConns
	poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	poolConfig.MaxConnLifetime = config.MaxConnLifetime
	poolConfig.HealthCheckPeriod = config.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	err = pool.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("ping db pool: %w", err)
	}
	log.Info().Msgf("Database connection established successfully at %s:%d/%s",
		config.Hostname, config.Port, config.Database)

	err = runDBMigrations(connString, migrationBaseDir)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("run database migrations: %w", err)
	}
	log.Info().Msg("Database migrations applied successfully")

	return &DB{
		config: config,
		pool:   pool,
		log:    log,
	}, nil
}

func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
		db.log.Info().Msg("Database connection pool closed")
	} else {
		db.log.Warn().Msg("Attempted to close a nil database connection pool")
	}
}

func AdjustListLimit(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = DefaultListLimit
	} else if limit > MaxListLimit {
		limit = MaxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
