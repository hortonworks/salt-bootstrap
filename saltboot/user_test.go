package saltboot

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var files map[string]string

func TestCreateUser(t *testing.T) {
	mockFunctions()
	defer endMockFunctions()

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

func TestChangePasswordToNewPassword(t *testing.T) {
	mockFunctions()
	defer endMockFunctions()

	master := SaltMaster{
		Auth: SaltAuth{Password: "newpassword"},
	}

	go ChangeUserPassword(master)

	checkExecutedCommands([]string{
		"cp /etc/shadow /etc/shadow.backup",
		"mv /etc/shadow.new /etc/shadow",
		"^chage -d (.*) saltuser",
	}, t)

	shadowFile := files["/etc/shadow.new"]
	if !strings.Contains(shadowFile, "root:!:18267:0:99999:7:::") {
		t.Error("Shadow file is missing root user")
	}
	if !strings.Contains(shadowFile, "saltuser") {
		t.Error("Shadow file is missing saltuser user")
	}
	if strings.Contains(shadowFile, "saltuser:$6$asdfghjklqwertzu$aDauWn56lHV2NozTj4.d9YFfgR4XWMjLvfzpOIQWDFpIvk6ZAbKSqoy7tN8cKHAs3mljtIdStax3Dlg2qRNfw0:19129:1:180:7:30::") {
		t.Error("Shadow file contains old password for saltuser")
	}
	if !strings.Contains(shadowFile, "bin:*:18113:0:99999:7:::") {
		t.Error("Shadow file is missing bin user")
	}
}

func TestChangePasswordToSamePassword(t *testing.T) {
	mockFunctions()
	defer endMockFunctions()

	master := SaltMaster{
		Auth: SaltAuth{Password: "oldpassword"},
	}

	ChangeUserPassword(master)
	if _, contains := files["/etc/shadow.new"]; contains {
		t.Error("Shadow file was written even though the same password was provided")
	}
}

func mockFunctions() {
	watchCommands = true
	files = map[string]string{}

	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		files[filename] = string(data)
		return nil
	}
	readFile = func(filename string) ([]byte, error) {
		return ioutil.ReadFile("testdata/" + filename)
	}
}

func endMockFunctions() {
	watchCommands = false
	files = map[string]string{}
}
