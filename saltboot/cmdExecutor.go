package saltboot

import (
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	ENV_TYPE          = "SALT_BOOTSTRAP_ENV_TYPE"
	EXECUTED_COMMANDS = "EXECUTED_COMMANDS"
)

func ExecCmd(executable string, args ...string) (outStr string, err error) {
	env := os.Getenv(ENV_TYPE)
	if env == "test" {
		os.Setenv(EXECUTED_COMMANDS, os.Getenv(EXECUTED_COMMANDS)+executable+" "+strings.Join(args, " ")+":")
		return "", nil
	} else {
		log.Printf("[cmdExecutor] Execute command: %s %s", executable, strings.Join(args, " "))
		command := exec.Command(executable, args...)
		out, e := command.CombinedOutput()
		if e != nil {
			err = e
		}
		if out != nil {
			outStr = strings.TrimSpace(string(out))
		}
		return outStr, err
	}
}
