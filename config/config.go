package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type GlobalConfig struct {
	Production   bool   `yaml:"production"`
	CookieSecret string `yaml:"cookie_secret"`
	CookieMaxAge int    `yaml:"cookie_max_age"`
}

type ProxyConfig struct {
	Listen       string            `yaml:"listen"`
	BasicAuths   map[string]string `yaml:"basic_auths"`
	CasServerUrl string            `yaml:"cas_server_url"`
	Backends     []string          `yaml:"backends"`
}

type Config struct {
	Global  GlobalConfig  `yaml:"global"`
	Proxies []ProxyConfig `yaml:"proxies"`
}

// Load parses the YAML input s into a Config.
func Load(s string) (*Config, error) {
	cfg := &Config{}
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile parses the given YAML file into a Config.
func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(string(content))
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
