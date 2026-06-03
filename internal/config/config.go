package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Credentials map[string]string `toml:"credentials"`
	AllowedHosts []string          `toml:"allowed_hosts"`
	allowedSet  map[string]bool
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.setDefaults()
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Credentials == nil {
		c.Credentials = make(map[string]string)
	}
	if c.AllowedHosts == nil {
		c.AllowedHosts = []string{}
	}
	c.allowedSet = make(map[string]bool, len(c.AllowedHosts))
	for _, h := range c.AllowedHosts {
		c.allowedSet[h] = true
	}
}

func (c *Config) AllowAll() {
	c.allowedSet["*"] = true
}

func (c *Config) IsHostAllowed(host string) bool {
	if c.allowedSet["*"] {
		return true
	}
	return c.allowedSet[host]
}

func (c *Config) GetCredentialURI(name string) (string, bool) {
	uri, ok := c.Credentials[name]
	return uri, ok
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/credproxy/credentials.toml"
}

func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/credproxy"
}
