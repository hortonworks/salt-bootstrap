package saltboot

import (
	"testing"
)

func TestCreateUser(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	master := SaltMaster{
		Auth: SaltAuth{Password: "passwd"},
	}

	go CreateUser(master, nil)

	checkExecutedCommands([]string{
		"grep saltuser /etc/passwd",
		"grep Ubuntu /etc/issue",
		"grep Debian /etc/issue",
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
		"^adduser --no-create-home -G wheel -s /sbin/nologin --password \\$6\\$([a-zA-Z\\$0-9/.]+) saltuser",
	}, t)
}
