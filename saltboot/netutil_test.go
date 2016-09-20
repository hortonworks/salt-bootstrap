package saltboot

import "testing"

func TestConfigfileFoundByEnv(t *testing.T) {
	getEnv := func(key string) string {
		switch key {
		case "SALTBOOT_CONFIG":
			return "test/.salt-bootstrap/security-config.yml"
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
		return "test", nil
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
			return "test/.salt-bootstrap/security-config.yml"
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
