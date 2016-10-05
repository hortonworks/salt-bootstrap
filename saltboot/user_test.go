package saltboot

import (
	"os"
	"regexp"
	"testing"
)

func TestCreateUser(t *testing.T) {
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

	master := SaltMaster{
		Auth: SaltAuth{Password: "passwd"},
	}

	CreateUser(master)

	pattern := "^grep saltuser /etc/passwd:adduser --no-create-home -G wheel -s /sbin/nologin --password \\$6\\$([a-zA-Z\\$0-9/.]+) saltuser:$"
	if m, err := regexp.MatchString(pattern, os.Getenv(EXECUTED_COMMANDS)); m == false || err != nil {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
}
