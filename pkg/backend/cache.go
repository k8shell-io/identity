package backend

import (
	"strconv"

	"github.com/bradfitz/gomemcache/memcache"
)

type CacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Timeout int    `yaml:"timeout"`
}

func NewCache(config CacheConfig) *memcache.Client {
	if !config.Enabled {
		return nil
	}

	memcache := memcache.New(config.Address + ":" + strconv.Itoa(config.Port))
	return memcache
}
