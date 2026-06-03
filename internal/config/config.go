package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type HostConfig struct {
	Credential string `toml:"credential"`
}

type Config struct {
	ProjectsDir string               `toml:"projects_dir"`
	Hosts       map[string]HostConfig `toml:"hosts"`
	hostsSet    map[string]bool
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
	cfg.SetDefaults()
	return &cfg, nil
}

func (c *Config) SetDefaults() {
	if c.Hosts == nil {
		c.Hosts = make(map[string]HostConfig)
	}
	c.hostsSet = make(map[string]bool, len(c.Hosts))
	for host := range c.Hosts {
		c.hostsSet[host] = true
	}
}

func (c *Config) Merge(overlay *Config) *Config {
	merged := &Config{
		ProjectsDir: c.ProjectsDir,
		Hosts:       make(map[string]HostConfig, len(c.Hosts)+len(overlay.Hosts)),
		hostsSet:    make(map[string]bool, len(c.Hosts)+len(overlay.Hosts)),
	}
	for host, hc := range c.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	for host, hc := range overlay.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	return merged
}

func (c *Config) IsHostAllowed(host string) bool {
	if c.hostsSet["*"] {
		return true
	}
	return c.hostsSet[host]
}

func (c *Config) GetCredentialURI(host string) (string, bool) {
	hc, ok := c.Hosts[host]
	if !ok {
		return "", false
	}
	return hc.Credential, true
}

func (c *Config) AllowAll() {
	c.hostsSet["*"] = true
}

func WalkProjectConfig(cwd, stopAt string) (string, error) {
	for {
		candidate := filepath.Join(cwd, ".credproxy.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		parent := filepath.Dir(cwd)
		if parent == cwd || cwd == stopAt {
			return "", nil
		}
		cwd = parent
	}
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "credproxy", "config.toml")
}

func DefaultProjectsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "code")
}

func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "credproxy")
}
