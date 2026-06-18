package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// EnvResolver is the minimal interface Config needs to resolve credential
// URIs. *resolver.Resolver satisfies it.
type EnvResolver interface {
	Resolve(ctx context.Context, uri string) (string, error)
}

// envResolveTimeout caps each individual provider call. The op CLI can hang
// on a 1Password auth prompt; this keeps startup from blocking indefinitely.
const envResolveTimeout = 30 * time.Second

type HostConfig struct {
	Credential string `toml:"credential"`
}

type ProfileConfig struct {
	Hosts map[string]HostConfig `toml:"hosts"`
	Env   map[string]string     `toml:"env"`
}

type Config struct {
	Env      map[string]string        `toml:"env"`
	Hosts    map[string]HostConfig    `toml:"hosts"`
	Profiles map[string]ProfileConfig `toml:"profiles"`
	hostsSet map[string]bool
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
	if c.Env == nil {
		c.Env = make(map[string]string)
	}
	if c.Profiles == nil {
		c.Profiles = make(map[string]ProfileConfig)
	}
	for name, p := range c.Profiles {
		if p.Hosts == nil {
			p.Hosts = make(map[string]HostConfig)
		}
		if p.Env == nil {
			p.Env = make(map[string]string)
		}
		c.Profiles[name] = p
	}
	c.hostsSet = make(map[string]bool, len(c.Hosts))
	for host := range c.Hosts {
		c.hostsSet[host] = true
	}
}


func (c *Config) Merge(overlay *Config) *Config {
	merged := &Config{
		Env:      make(map[string]string, len(c.Env)+len(overlay.Env)),
		Hosts:    make(map[string]HostConfig, len(c.Hosts)+len(overlay.Hosts)),
		Profiles: make(map[string]ProfileConfig, len(c.Profiles)+len(overlay.Profiles)),
		hostsSet: make(map[string]bool, len(c.Hosts)+len(overlay.Hosts)),
	}
	for k, v := range c.Env {
		merged.Env[k] = v
	}
	for k, v := range overlay.Env {
		merged.Env[k] = v
	}
	for host, hc := range c.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	for host, hc := range overlay.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	for name, p := range c.Profiles {
		merged.Profiles[name] = p
	}
	for name, p := range overlay.Profiles {
		if existing, ok := merged.Profiles[name]; ok {
			ep := ProfileConfig{
				Hosts: make(map[string]HostConfig, len(existing.Hosts)+len(p.Hosts)),
				Env:   make(map[string]string, len(existing.Env)+len(p.Env)),
			}
			for k, v := range existing.Env {
				ep.Env[k] = v
			}
			for k, v := range p.Env {
				ep.Env[k] = v
			}
			for h, hc := range existing.Hosts {
				ep.Hosts[h] = hc
			}
			for h, hc := range p.Hosts {
				ep.Hosts[h] = hc
			}
			merged.Profiles[name] = ep
		} else {
			merged.Profiles[name] = p
		}
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

func (c *Config) EnvVars() map[string]string {
	return c.Env
}

// ResolveEnv walks c.Env and resolves any value starting with "op://" through
// the supplied EnvResolver, replacing the URI with the resolved secret. Other
// values pass through untouched. Resolutions run concurrently; each call has
// its own 30s deadline. The first resolution error fails the whole batch and
// is returned joined with any other errors.
func (c *Config) ResolveEnv(ctx context.Context, r EnvResolver) error {
	type pending struct {
		key string
		uri string
	}
	var work []pending
	for k, v := range c.Env {
		if strings.HasPrefix(v, "op://") {
			work = append(work, pending{key: k, uri: v})
		}
	}
	if len(work) == 0 {
		return nil
	}

	type result struct {
		key   string
		value string
		err   error
	}
	results := make(chan result, len(work))
	var wg sync.WaitGroup
	for _, p := range work {
		wg.Add(1)
		go func(p pending) {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(ctx, envResolveTimeout)
			defer cancel()
			val, err := r.Resolve(callCtx, p.uri)
			results <- result{key: p.key, value: val, err: err}
		}(p)
	}
	wg.Wait()
	close(results)

	var errs []error
	for res := range results {
		if res.err != nil {
			errs = append(errs, fmt.Errorf("resolving env %s: %w", res.key, res.err))
			continue
		}
		c.Env[res.key] = res.value
	}
	return errors.Join(errs...)
}

func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	return names
}

func (c *Config) ApplyProfile(name string) (*Config, error) {
	if name == "" {
		return c, nil
	}
	profile, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found; available: %v", name, c.ProfileNames())
	}
	result := &Config{
		Env:      make(map[string]string, len(c.Env)+len(profile.Env)),
		Hosts:    make(map[string]HostConfig, len(c.Hosts)+len(profile.Hosts)),
		Profiles: c.Profiles,
		hostsSet: make(map[string]bool, len(c.Hosts)+len(profile.Hosts)),
	}
	for k, v := range c.Env {
		result.Env[k] = v
	}
	for k, v := range profile.Env {
		result.Env[k] = v
	}
	for host, hc := range c.Hosts {
		result.Hosts[host] = hc
		result.hostsSet[host] = true
	}
	for host, hc := range profile.Hosts {
		result.Hosts[host] = hc
		result.hostsSet[host] = true
	}
	return result, nil
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

func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "credproxy")
}
