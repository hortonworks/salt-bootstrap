package saltboot

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

const (
	httpsEnabledKey        = "SALTBOOT_HTTPS_ENABLED"
	portKey                = "SALTBOOT_PORT"
	defaultPort            = 7070
	httpsPortKey           = "SALTBOOT_HTTPS_PORT"
	defaultHttpsPort       = 7071
	httpsCertFileKey       = "SALTBOOT_HTTPS_CERT_FILE"
	defaultHttpsCertFile   = "/etc/certs/cluster.pem"
	httpsKeyFileKey        = "SALTBOOT_HTTPS_KEY_FILE"
	defaultHttpsKeyFile    = "/etc/certs/cluster-key.pem"
	httpsCaCertFileKey     = "SALTBOOT_HTTPS_CACERT_FILE"
	defaultHttpsCaCertFile = "/etc/certs/ca.pem"
	minTlsVersionKey       = "SALTBOOT_MIN_TLS_VERSION"
	defaultMinTlsVersion   = tls.VersionTLS12
	maxTlsVersionKey       = "SALTBOOT_MAX_TLS_VERSION"
	defaultMaxTlsVersion   = tls.VersionTLS13
	cipherSuitesKey        = "SALTBOOT_CIPHER_SUITES"

	userKey          = "SALTBOOT_USER"
	passwdKey        = "SALTBOOT_PASSWORD"
	signKey          = "SALTBOOT_SIGN_KEY"
	configLocKey     = "SALTBOOT_CONFIG"
	defaultConfigLoc = "/etc/salt-bootstrap/security-config.yml"
)

var tlsVersionMap = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

/**
 * This slice matches the list of cipher suites specified in https://pkg.go.dev/crypto/tls@go1.14.3#pkg-constants
 * Only the TLS 1.0-1.2 cipher suites are listed, since according to the go documentation "...TLS 1.3 ciphersuites are not configurable."
 */
var cipherSuiteMap = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

type HttpsConfig struct {
	CertFile      string   `json:"certFile" yaml:"certFile"`
	KeyFile       string   `json:"keyFile" yaml:"keyFile"`
	CaCertFile    string   `json:"caCertFile" yaml:"caCertFile"`
	MinTlsVersion uint16   `json:"minTlsVersion" yaml:"minTlsVersion"`
	MaxTlsVersion uint16   `json:"maxTlsVersion" yaml:"maxTlsVersion"`
	CipherSuites  []uint16 `json:"cipherSuites" yaml:"cipherSuites"`
}

type SecurityConfig struct {
	Username      string `json:"username" yaml:"username"`
	Password      string `json:"password" yaml:"password"`
	SignVerifyKey string `json:"signKey" yaml:"signKey"`
}

func defaultCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}
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

func DetermineBootstrapPort(httpsEnabled bool) int {
	if httpsEnabled {
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
	minTlsVersionStr := os.Getenv(minTlsVersionKey)
	maxTlsVersionStr := os.Getenv(maxTlsVersionKey)
	cipherSuitesStr := os.Getenv(cipherSuitesKey)

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
		httpsConfig.CaCertFile = defaultHttpsCaCertFile
		log.Printf("[GetHttpsConfig] using default ca cert file: %s", defaultHttpsCaCertFile)
	} else {
		httpsConfig.CaCertFile = caCertFileStr
	}
	if minTlsVersionStr == "" {
		httpsConfig.MinTlsVersion = defaultMinTlsVersion
		log.Printf("[GetHttpsConfig] using default min TLS version: %s", tlsVersionToString(defaultMinTlsVersion))
	} else {
		minTlsVersion, valid := tlsVersionMap[minTlsVersionStr]
		if !valid {
			log.Fatalf("[GetHttpsConfig] The specified TLS version is not a valid TLS version: %s", minTlsVersionStr)
		}
		httpsConfig.MinTlsVersion = minTlsVersion
	}
	if maxTlsVersionStr == "" {
		httpsConfig.MaxTlsVersion = defaultMaxTlsVersion
		log.Printf("[GetHttpsConfig] using default max TLS version: %s", tlsVersionToString(defaultMaxTlsVersion))
	} else {
		maxTlsVersion, valid := tlsVersionMap[maxTlsVersionStr]
		if !valid {
			log.Fatalf("[GetHttpsConfig] The specified TLS version is not a valid TLS version: %s", maxTlsVersionStr)
		}
		httpsConfig.MaxTlsVersion = maxTlsVersion
	}
	if cipherSuitesStr == "" {
		httpsConfig.CipherSuites = defaultCipherSuites()
		log.Printf("[GetHttpsConfig] using default list of cipher suites: %s", MapUint16ToString(defaultCipherSuites(), cipherSuiteToString))
	} else {
		httpsConfig.CipherSuites = MapStringToUint16(strings.Split(cipherSuitesStr, ","), func(s string) uint16 {
			cipherSuite, valid := cipherSuiteMap[s]
			if !valid {
				log.Fatalf("[GetHttpsConfig] The specified cipher suite is not a valid cipher suite: %s", s)
			}
			return cipherSuite
		})
	}
	return httpsConfig
}

func GetConcatenatedCertFilePath(httpsConfig HttpsConfig) (string, error) {
	tmpFile, err := os.CreateTemp("/tmp", "saltboot-*.pem")
	defer tmpFile.Close()
	if err != nil {
		return "", err
	}
	serverCert, err := os.ReadFile(httpsConfig.CertFile)
	if err != nil {
		return "", err
	}
	caCert, err := os.ReadFile(httpsConfig.CaCertFile)
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

func tlsVersionToString(tlsVersion uint16) string {
	for str, constant := range tlsVersionMap {
		if constant == tlsVersion {
			return str
		}
	}
	return fmt.Sprintf("(0x%04x)", tlsVersion)
}

func cipherSuiteToString(cipherSuite uint16) string {
	for str, constant := range cipherSuiteMap {
		if constant == cipherSuite {
			return str
		}
	}
	return fmt.Sprintf("(0x%04x)", cipherSuite)
}

func DetermineSecurityDetails(getEnv func(key string) string, securityConfig func() string) (*SecurityConfig, error) {
	var config SecurityConfig
	configLoc := strings.TrimSpace(getEnv(configLocKey))
	if len(configLoc) == 0 {
		configLoc = securityConfig()
	}

	content, err := os.ReadFile(configLoc)
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
