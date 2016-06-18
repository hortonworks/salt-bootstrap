package saltboot

import (
	"log"
	"os/exec"
	"strings"
)

func ExecCmd(executable string, args ...string) (outStr string, err error) {
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
