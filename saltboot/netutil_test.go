package saltboot

import (
	"os"
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

	port := DetermineHttpsPort()

	if port != 8080 {
		t.Errorf("port does not match the custom HTTPS port %d == %d", 8080, port)
	}

	os.Unsetenv(httpsPortKey)
}

func TestDetermineHttpPortDefault(t *testing.T) {
	port := DetermineHttpPort()

	if port != defaultPort {
		t.Errorf("port does not match the default port %d == %d", defaultPort, port)
	}
}

func TestDetermineHttpPortCustom(t *testing.T) {
	os.Setenv(portKey, "8080")

	port := DetermineHttpPort()

	if port != 8080 {
		t.Errorf("port does not match the custom port %d == %d", 8080, port)
	}

	os.Unsetenv(portKey)
}

func TestGetHttpsConfigDefault(t *testing.T) {
	httpsConfig := GetHttpsConfig()

	if httpsConfig.CertFile != defaultHttpsCertFile {
		t.Errorf("cert file does not match the default %s == %s", defaultHttpsCertFile, httpsConfig.CertFile)
	}
	if httpsConfig.KeyFile != defaultHttpsKeyFile {
		t.Errorf("key file does not match the default %s == %s", defaultHttpsKeyFile, httpsConfig.KeyFile)
	}
	if httpsConfig.CaCertFile != defaultHttpsCaCertFileKey {
		t.Errorf("ca cert file does not match the default %s == %s", defaultHttpsCaCertFileKey, httpsConfig.CaCertFile)
	}
}

func TestGetHttpsConfigCustom(t *testing.T) {
	os.Setenv(httpsCertFileKey, "path/certfile.pem")
	os.Setenv(httpsKeyFileKey, "path/keyfile.pem")
	os.Setenv(httpsCaCertFileKey, "path/ca.pem")

	httpsConfig := GetHttpsConfig()

	if httpsConfig.CertFile != "path/certfile.pem" {
		t.Errorf("cert file does not match the default %s == %s", "path/certfile.pem", httpsConfig.CertFile)
	}
	if httpsConfig.KeyFile != "path/keyfile.pem" {
		t.Errorf("key file does not match the default %s == %s", "path/keyfile.pem", httpsConfig.KeyFile)
	}
	if httpsConfig.CaCertFile != "path/ca.pem" {
		t.Errorf("ca cert file does not match the default %s == %s", "path/ca.pem", httpsConfig.CaCertFile)
	}

	os.Unsetenv(httpsCertFileKey)
	os.Unsetenv(httpsKeyFileKey)
	os.Unsetenv(httpsCaCertFileKey)
}

func TestGetConcatenatedCertFilePath(t *testing.T) {

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
