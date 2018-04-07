package saltboot

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

var commandExecutor = func(executable string, args ...string) ([]byte, error) {
	return exec.Command(executable, args...).CombinedOutput()
}

func ExecCmd(executable string, args ...string) (outStr string, err error) {
	command := executable + " " + strings.Join(args, " ")
	log.Printf("[cmdExecutor] Execute command: %s", command)
	out, e := commandExecutor(executable, args...)
	if e != nil {
		err = errors.New(fmt.Sprintf("Failed to execute command: '%s', err: %s", command, e.Error()))
	}
	if out != nil {
		outStr = strings.TrimSpace(string(out))
	}
	return outStr, err
}
