package saltboot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
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

// timedCommandExecutor kills the command once timeout passes. It returns stdout only and puts stderr in the
// error, so warnings on stderr cannot corrupt machine-readable output.
var timedCommandExecutor = func(timeout time.Duration, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// do not wait for children that inherited the pipes after the command itself was killed
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	// a command that finished successfully just before the deadline keeps its output
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	} else if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), err
}

func ExecCmdWithTimeout(timeout time.Duration, executable string, args ...string) (outStr string, err error) {
	command := executable + " " + strings.Join(args, " ")
	log.Printf("[cmdExecutor] Execute command with %s timeout: %s", timeout, command)
	out, e := timedCommandExecutor(timeout, executable, args...)
	if e != nil {
		err = errors.New(fmt.Sprintf("Failed to execute command: '%s', err: %s", command, e.Error()))
	}
	if out != nil {
		outStr = strings.TrimSpace(string(out))
	}
	return outStr, err
}
