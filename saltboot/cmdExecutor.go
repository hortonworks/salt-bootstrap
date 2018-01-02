package saltboot

import (
	"log"
	"os/exec"
	"strings"
)

const (
	ENV_TYPE = "SALT_BOOTSTRAP_ENV_TYPE"
)

var commandExecutor = func(executable string, args ...string) ([]byte, error) {
	return exec.Command(executable, args...).CombinedOutput()
}

func ExecCmd(executable string, args ...string) (outStr string, err error) {
	log.Printf("[cmdExecutor] Execute command: %s %s", executable, strings.Join(args, " "))
	out, e := commandExecutor(executable, args...)
	if e != nil {
		err = e
	}
	if out != nil {
		outStr = strings.TrimSpace(string(out))
	}
	return outStr, err
}
