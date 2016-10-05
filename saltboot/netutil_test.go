package saltboot

import (
	"os"
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

	config, _ := DetermineSecurityDetails(getEnv, nil)
	expected := SecurityConfig{Username: "name", Password: "pwd", SignVerifyKey: "key"}
	if config != expected {
		t.Errorf("Not match %s == %s", expected, config)
	}
}

func TestConfigfileFoundByHomedir(t *testing.T) {
	getEnv := func(key string) string {
		return ""
	}
	getHomeDir := func() (string, error) {
		return "testdata", nil
	}

	config, _ := DetermineSecurityDetails(getEnv, getHomeDir)
	expected := SecurityConfig{Username: "name", Password: "pwd", SignVerifyKey: "key"}
	if config != expected {
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

	config, _ := DetermineSecurityDetails(getEnv, nil)
	expected := SecurityConfig{Username: "name-ower", Password: "pwd-ower", SignVerifyKey: "key-ower"}
	if config != expected {
		t.Errorf("Not match %s == %s", expected, config)
	}
}
