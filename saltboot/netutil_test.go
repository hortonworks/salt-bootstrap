package saltboot

import (
	"crypto/tls"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDetermineBootstrapPortDefaultHttpsFalse(t *testing.T) {
	port := DetermineBootstrapPort(false)

	if port != defaultPort {
		t.Errorf("port does not match the default port %d == %d", defaultPort, port)
	}
}

func TestDetermineBootstrapPortDefaultHttps(t *testing.T) {
	port := DetermineBootstrapPort(true)

	if port != defaultHttpsPort {
		t.Errorf("port does not match the HTTPS default port %d == %d", defaultHttpsPort, port)
	}
}

func TestDetermineBootstrapPortCustom(t *testing.T) {
	os.Setenv(portKey, "8080")
	defer os.Unsetenv(portKey)

	port := DetermineBootstrapPort(false)

	if port != 8080 {
		t.Errorf("port does not match the custom port %d == %d", 8080, port)
	}
}

func TestDetermineBootstrapPortCustomHttps(t *testing.T) {
	os.Setenv(httpsPortKey, "8080")
	defer os.Unsetenv(httpsPortKey)

	port := DetermineBootstrapPort(true)

	if port != 8080 {
		t.Errorf("port does not match the custom HTTPS port %d == %d", 8080, port)
	}
}

func TestDetermineHttpsPortDefault(t *testing.T) {
	port := DetermineHttpsPort()

	if port != defaultHttpsPort {
		t.Errorf("port does not match the default HTTPS port %d == %d", defaultHttpsPort, port)
	}
}

func TestDetermineHttpsPortCustom(t *testing.T) {
	os.Setenv(httpsPortKey, "8080")
	defer os.Unsetenv(httpsPortKey)

	port := DetermineHttpsPort()

	if port != 8080 {
		t.Errorf("port does not match the custom HTTPS port %d == %d", 8080, port)
	}
}

func TestDetermineHttpPortDefault(t *testing.T) {
	port := DetermineHttpPort()

	if port != defaultPort {
		t.Errorf("port does not match the default port %d == %d", defaultPort, port)
	}
}

func TestDetermineHttpPortCustom(t *testing.T) {
	os.Setenv(portKey, "8080")
	defer os.Unsetenv(portKey)

	port := DetermineHttpPort()

	if port != 8080 {
		t.Errorf("port does not match the custom port %d == %d", 8080, port)
	}
}

func TestGetHttpsConfigDefault(t *testing.T) {
	httpsConfig := GetHttpsConfig()

	if httpsConfig.CertFile != defaultHttpsCertFile {
		t.Errorf("cert file does not match the default %s == %s", defaultHttpsCertFile, httpsConfig.CertFile)
	}
	if httpsConfig.KeyFile != defaultHttpsKeyFile {
		t.Errorf("key file does not match the default %s == %s", defaultHttpsKeyFile, httpsConfig.KeyFile)
	}
	if httpsConfig.CaCertFile != defaultHttpsCaCertFile {
		t.Errorf("ca cert file does not match the default %s == %s", defaultHttpsCaCertFile, httpsConfig.CaCertFile)
	}
	if httpsConfig.MinTlsVersion != defaultMinTlsVersion {
		t.Errorf("min TLS version does not match the default %d == %d", defaultMinTlsVersion, httpsConfig.MinTlsVersion)
	}
	if httpsConfig.MaxTlsVersion != defaultMaxTlsVersion {
		t.Errorf("max TLS version does not match the default %d == %d", defaultMaxTlsVersion, httpsConfig.MaxTlsVersion)
	}
	if !EqualUint16Slices(httpsConfig.CipherSuites, defaultCipherSuites()) {
		t.Errorf("list of cipher suites does not match the default list %d == %d", defaultCipherSuites(), httpsConfig.CipherSuites)
	}
}

func TestGetHttpsConfigCustom(t *testing.T) {
	os.Setenv(httpsCertFileKey, "path/certfile.pem")
	os.Setenv(httpsKeyFileKey, "path/keyfile.pem")
	os.Setenv(httpsCaCertFileKey, "path/ca.pem")
	os.Setenv(minTlsVersionKey, "1.1")
	os.Setenv(maxTlsVersionKey, "1.2")
	os.Setenv(cipherSuitesKey, "TLS_ECDHE_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384")
	defer os.Unsetenv(httpsCertFileKey)
	defer os.Unsetenv(httpsKeyFileKey)
	defer os.Unsetenv(httpsCaCertFileKey)
	defer os.Unsetenv(minTlsVersionKey)
	defer os.Unsetenv(maxTlsVersionKey)
	defer os.Unsetenv(cipherSuitesKey)

	httpsConfig := GetHttpsConfig()

	if httpsConfig.CertFile != "path/certfile.pem" {
		t.Errorf("cert file does not match the one specified %s == %s", "path/certfile.pem", httpsConfig.CertFile)
	}
	if httpsConfig.KeyFile != "path/keyfile.pem" {
		t.Errorf("key file does not match the one specified %s == %s", "path/keyfile.pem", httpsConfig.KeyFile)
	}
	if httpsConfig.CaCertFile != "path/ca.pem" {
		t.Errorf("ca cert file does not match the one specified %s == %s", "path/ca.pem", httpsConfig.CaCertFile)
	}
	if httpsConfig.MinTlsVersion != tls.VersionTLS11 {
		t.Errorf("min TLS version does not match the one specified %d == %d", tls.VersionTLS11, httpsConfig.MinTlsVersion)
	}
	if httpsConfig.MaxTlsVersion != tls.VersionTLS12 {
		t.Errorf("max TLS version does not match the one specified %d == %d", tls.VersionTLS12, httpsConfig.MaxTlsVersion)
	}
	expectedCipherSuites := []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}
	if !EqualUint16Slices(httpsConfig.CipherSuites, expectedCipherSuites) {
		t.Errorf("list of cipher suites does not match the one specified %d == %d", expectedCipherSuites, httpsConfig.CipherSuites)
	}
}

func TestGetHttpsConfigInvalidMinTlsVersion(t *testing.T) {
	os.Setenv(minTlsVersionKey, "0.9")
	defer os.Unsetenv(minTlsVersionKey)
	if os.Getenv("SALTBOOT_MIN_TLS_CRASHER") == "1" {
		GetHttpsConfig()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestGetHttpsConfigInvalidMinTlsVersion")
	cmd.Env = append(cmd.Env, "SALTBOOT_MIN_TLS_CRASHER=1")
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		log.Printf("Process exited as expected: %v", err)
		return
	}
	t.Errorf("Process did not exit as expected: %v", err)
}

func TestGetHttpsConfigInvalidMaxTlsVersion(t *testing.T) {
	os.Setenv(maxTlsVersionKey, "0.9")
	defer os.Unsetenv(maxTlsVersionKey)
	if os.Getenv("SALTBOOT_MAX_TLS_CRASHER") == "1" {
		GetHttpsConfig()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestGetHttpsConfigInvalidMaxTlsVersion")
	cmd.Env = append(cmd.Env, "SALTBOOT_MAX_TLS_CRASHER=1")
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		log.Printf("Process exited as expected: %v", err)
		return
	}
	t.Errorf("Process did not exit as expected: %v", err)
}

func TestGetHttpsConfigInvalidCipherSuite(t *testing.T) {
	os.Setenv(cipherSuitesKey, "TLS_ECDHE_RSA_WITH_RC4_128_SHA,NOT_GOOD_VERY_BAD_CIPHER_SUITE,TLS_RSA_WITH_AES_256_GCM_SHA384")
	defer os.Unsetenv(cipherSuitesKey)
	if os.Getenv("SALTBOOT_CIPHER_SUITES_CRASHER") == "1" {
		GetHttpsConfig()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestGetHttpsConfigInvalidCipherSuite")
	cmd.Env = append(cmd.Env, "SALTBOOT_CIPHER_SUITES_CRASHER=1")
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		log.Printf("Process exited as expected: %v", err)
		return
	}
	t.Errorf("Process did not exit as expected: %v", err)
}

func TestConfigfileFoundByEnv(t *testing.T) {
	getEnv := func(key string) string {
		switch key {
		case "SALTBOOT_CONFIG":
			return "testdata/.salt-bootstrap/security-config.yml"
		default:
			return ""
		}
	}

	config, err := DetermineSecurityDetails(getEnv, nil)
	if err != nil {
		t.Errorf("Error must be nil")
	}

	if config == nil {
		t.Errorf("Config must not be nil")
	}
	expected := SecurityConfig{Username: "name", Password: "pwd", SignVerifyKey: "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtwnm1Tk0Yq0sXRC/1wq4nHLpAI5K6fEQX5/y8Zl/45pt2/BPGV6i2f3hTH+6U60RHdpUQgu7XhLFKRbznh6G3uZKxEajQHBLCoW3SJXgeWdeNlA759mUdxzIqukTOPvFJj/7WbYDD6RBgVya4hC3bbtBEehcTFoeajfVBSrK4niN/8cPJLquVNTXK428J+OQkQs7DGnc1lt/Gp+LuRFKfLH4ll/+D6mlNZqpm2Mb3lFImD0SnmyO1ktewBSfoTDjiRxhQ9eOd9xrKfvRlzRf6DVXP1CwEU1b4hSXd98F5Vt4VpJEoakIbBVju/MrcYh1VcO9KFrGt1wjuQSHI9515QIDAQAB\n" + "-----END PUBLIC KEY-----"}
	if *config != expected {
		t.Errorf("Not match %s == %s", expected, config)
	}

}

func TestConfigfileFoundByHomedir(t *testing.T) {
	getEnv := func(key string) string {
		return ""
	}
	getConfigLoc := func() string {
		return "testdata/.salt-bootstrap/security-config.yml"
	}

	config, err := DetermineSecurityDetails(getEnv, getConfigLoc)
	if err != nil {
		t.Errorf("Error must be nil")
	}

	if config == nil {
		t.Errorf("Config must not be nil")
	}
	expected := SecurityConfig{Username: "name", Password: "pwd", SignVerifyKey: "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtwnm1Tk0Yq0sXRC/1wq4nHLpAI5K6fEQX5/y8Zl/45pt2/BPGV6i2f3hTH+6U60RHdpUQgu7XhLFKRbznh6G3uZKxEajQHBLCoW3SJXgeWdeNlA759mUdxzIqukTOPvFJj/7WbYDD6RBgVya4hC3bbtBEehcTFoeajfVBSrK4niN/8cPJLquVNTXK428J+OQkQs7DGnc1lt/Gp+LuRFKfLH4ll/+D6mlNZqpm2Mb3lFImD0SnmyO1ktewBSfoTDjiRxhQ9eOd9xrKfvRlzRf6DVXP1CwEU1b4hSXd98F5Vt4VpJEoakIbBVju/MrcYh1VcO9KFrGt1wjuQSHI9515QIDAQAB\n" + "-----END PUBLIC KEY-----"}
	if *config != expected {
		t.Errorf("Not match %s == %s", expected, config)
	}

}

func TestUsernameAndPasswordAndSignkeyFoundByEnv(t *testing.T) {
	getEnv := func(key string) string {
		switch key {
		case "SALTBOOT_CONFIG":
			return "testdata/.salt-bootstrap/security-config.yml"
		case "SALTBOOT_USER":
			return "name-ower"
		case "SALTBOOT_PASSWORD":
			return "pwd-ower"
		case "SALTBOOT_SIGN_KEY":
			return "key-ower"
		default:
			return ""
		}
	}

	config, err := DetermineSecurityDetails(getEnv, nil)
	if config != nil {
		t.Errorf("Result must be nil")
	}
	if err == nil {
		t.Errorf("Error shall be raised when invalid data is passed")
	}
	if !strings.Contains(err.Error(), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("Error message shall contain %s, but %s", "-----BEGIN PUBLIC KEY-----", err.Error())
	}
}

func TestUsernameAndPasswordAndSignkeyFoundByEnvWithMissingEnd(t *testing.T) {
	getEnv := func(key string) string {
		switch key {
		case "SALTBOOT_CONFIG":
			return "testdata/.salt-bootstrap/security-config.yml"
		case "SALTBOOT_USER":
			return "name-ower"
		case "SALTBOOT_PASSWORD":
			return "pwd-ower"
		case "SALTBOOT_SIGN_KEY":
			return "-----BEGIN PUBLIC KEY-----key-ower-----END PUBLIC KE"
		default:
			return ""
		}
	}

	config, err := DetermineSecurityDetails(getEnv, nil)
	if config != nil {
		t.Errorf("Result must be nil")
	}
	if err == nil {
		t.Errorf("Error shall be raised when invalid data is passed")
	}
	if !strings.Contains(err.Error(), "-----END PUBLIC KEY-----") {
		t.Errorf("Error message shall contain %s, but %s", "-----END PUBLIC KEY-----", err.Error())
	}
}
