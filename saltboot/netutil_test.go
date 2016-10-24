package saltboot

import (
	"os"
	"strings"
	"testing"
)

func TestDetermineBootstrapPortDefault(t *testing.T) {
	port := DetermineBootstrapPort()

	if port != defaultPort {
		t.Errorf("port not match to default %d == %d", defaultPort, port)
	}
}

func TestDetermineBootstrapPortCustom(t *testing.T) {
	os.Setenv(portKey, "8080")

	port := DetermineBootstrapPort()

	if port != 8080 {
		t.Errorf("port not match to default %d == %d", 8080, port)
	}
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
