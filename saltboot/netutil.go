package saltboot

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

const (
	defaultPort      = 7070
	portKey          = "SALTBOOT_PORT"
	userKey          = "SALTBOOT_USER"
	passwdKey        = "SALTBOOT_PASSWORD"
	signKey          = "SALTBOOT_SIGN_KEY"
	configLocKey     = "SALTBOOT_CONFIG"
	defaultConfigLoc = "/etc/salt-bootstrap/security-config.yml"
)

type SecurityConfig struct {
	Username      string `json:"username" yaml:"username"`
	Password      string `json:"password" yaml:"password"`
	SignVerifyKey string `json:"signKey" yaml:"signKey"`
}

func defaultSecurityConfigLoc() string {
	return defaultConfigLoc
}

func (sc *SecurityConfig) validate() error {
	if len(sc.Username) == 0 {
		return fmt.Errorf("Username is not configred for salt-bootstrap")
	}
	if len(sc.Password) == 0 {
		return fmt.Errorf("Password is not configred for salt-bootstrap")
	}
	if len(sc.SignVerifyKey) == 0 {
		return fmt.Errorf("SignVerifyKey is not configred for salt-bootstrap")
	}
	if !strings.Contains(sc.SignVerifyKey, "-----BEGIN PUBLIC KEY-----") {
		return fmt.Errorf("SignVerifyKey is not valid missing: -----BEGIN PUBLIC KEY-----")
	}
	if !strings.Contains(sc.SignVerifyKey, "-----END PUBLIC KEY-----") {
		return fmt.Errorf("SignVerifyKey is not valid missing: -----END PUBLIC KEY-----")
	}
	return nil
}

func DetermineBootstrapPort() int {
	portStr := os.Getenv(portKey)
	log.Printf("[determineBootstrapPort] SALTBOOT_PORT: %s", portStr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = defaultPort
		log.Printf("[determineBootstrapPort] using default port: %d", port)
	}

	return port
}

func DetermineSecurityDetails(getEnv func(key string) string, securityConfig func() string) (*SecurityConfig, error) {
	var config SecurityConfig
	configLoc := strings.TrimSpace(getEnv(configLocKey))
	if len(configLoc) == 0 {
		configLoc = securityConfig()
	}

	content, err := ioutil.ReadFile(configLoc)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}

	if u := strings.TrimSpace(getEnv(userKey)); len(u) > 0 {
		config.Username = u
	}
	if p := strings.TrimSpace(getEnv(passwdKey)); len(p) > 0 {
		config.Password = p
	}
	if k := strings.TrimSpace(getEnv(signKey)); len(k) > 0 {
		config.SignVerifyKey = k
	}

	err = config.validate()
	if err != nil {
		log.Print("[determineAuthCredentials] Unable to create valid configuration details.")
		return nil, err
	}
	return &config, nil
}
