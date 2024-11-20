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
	httpsEnabledKey           = "SALTBOOT_HTTPS_ENABLED"
	portKey                   = "SALTBOOT_PORT"
	defaultPort               = 7070
	httpsPortKey              = "SALTBOOT_HTTPS_PORT"
	defaultHttpsPort          = 7071
	httpsCertFileKey          = "SALTBOOT_HTTPS_CERT_FILE"
	defaultHttpsCertFile      = "/etc/certs/cluster.pem"
	httpsKeyFileKey           = "SALTBOOT_HTTPS_KEY_FILE"
	defaultHttpsKeyFile       = "/etc/certs/cluster-key.pem"
	httpsCaCertFileKey        = "SALTBOOT_HTTPS_CACERT_FILE"
	defaultHttpsCaCertFileKey = "/etc/certs/ca.pem"

	userKey          = "SALTBOOT_USER"
	passwdKey        = "SALTBOOT_PASSWORD"
	signKey          = "SALTBOOT_SIGN_KEY"
	configLocKey     = "SALTBOOT_CONFIG"
	defaultConfigLoc = "/etc/salt-bootstrap/security-config.yml"
)

type HttpsConfig struct {
	CertFile   string `json:"certFile" yaml:"certFile"`
	KeyFile    string `json:"keyFile" yaml:"keyFile"`
	CaCertFile string `json:"caCertFile" yaml:"caCertFile"`
}

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
	if HttpsEnabled() {
		return DetermineHttpsPort()
	} else {
		return DetermineHttpPort()
	}
}

func HttpsEnabled() bool {
	httpsEnabled := os.Getenv(httpsEnabledKey)
	log.Printf("[HttpsEnabled] %s: %s", httpsEnabledKey, httpsEnabled)
	return httpsEnabled != "" && strings.ToLower(httpsEnabled) != "false"
}

func DetermineHttpsPort() int {
	portStr := os.Getenv(httpsPortKey)
	log.Printf("[DetermineHttpsPort] %s: %s", httpsPortKey, portStr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("[DetermineHttpsPort] using default HTTPS port: %d", defaultHttpsPort)
		port = defaultHttpsPort
	}
	return port
}

func DetermineHttpPort() int {
	portStr := os.Getenv(portKey)
	log.Printf("[DetermineHttpPort] %s: %s", portKey, portStr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("[DetermineHttpPort] using default HTTP port: %d", defaultPort)
		port = defaultPort
	}
	return port
}

func GetHttpsConfig() HttpsConfig {
	var httpsConfig HttpsConfig
	certFileStr := os.Getenv(httpsCertFileKey)
	keyFileStr := os.Getenv(httpsKeyFileKey)
	caCertFileStr := os.Getenv(httpsCaCertFileKey)
	log.Printf("[GetHttpsConfig] %s: %s", httpsCertFileKey, certFileStr)
	log.Printf("[GetHttpsConfig] %s: %s", httpsKeyFileKey, keyFileStr)
	log.Printf("[GetHttpsConfig] %s: %s", httpsCaCertFileKey, caCertFileStr)

	if certFileStr == "" {
		httpsConfig.CertFile = defaultHttpsCertFile
		log.Printf("[GetHttpsConfig] using default cert file: %s", defaultHttpsCertFile)
	} else {
		httpsConfig.CertFile = certFileStr
	}
	if keyFileStr == "" {
		httpsConfig.KeyFile = defaultHttpsKeyFile
		log.Printf("[GetHttpsConfig] using default key file: %s", defaultHttpsKeyFile)
	} else {
		httpsConfig.KeyFile = keyFileStr
	}
	if caCertFileStr == "" {
		httpsConfig.CaCertFile = defaultHttpsCaCertFileKey
		log.Printf("[GetHttpsConfig] using default ca cert file: %s", defaultHttpsCaCertFileKey)
	} else {
		httpsConfig.CaCertFile = caCertFileStr
	}
	return httpsConfig
}

func GetConcatenatedCertFilePath(httpsConfig HttpsConfig) (string, error) {
	tmpFile, err := ioutil.TempFile("/tmp", "saltboot-*.pem")
	defer tmpFile.Close()
	if err != nil {
		return "", err
	}
	serverCert, err := ioutil.ReadFile(httpsConfig.CertFile)
	if err != nil {
		return "", err
	}
	caCert, err := ioutil.ReadFile(httpsConfig.CaCertFile)
	if err != nil {
		return "", err
	}
	_, err = tmpFile.Write(serverCert)
	if err != nil {
		return "", err
	}
	_, err = tmpFile.Write(caCert)
	if err != nil {
		return "", err
	}
	log.Printf("[GetConcatenatedCertFilePath] concatenated cert file successfully created: %s", tmpFile.Name())
	return tmpFile.Name(), nil
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
