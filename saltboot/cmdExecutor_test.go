package saltboot

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var originalExecutor = commandExecutor
var watchCommands = false
var commands = make(chan string, 0)

func init() {
	commandExecutor = func(executable string, args ...string) ([]byte, error) {
		command := executable
		if args != nil && len(args) != 0 {
			command += " " + strings.Join(args, " ")
		}
		if watchCommands {
			commands <- command
		}
		return make([]byte, 0), nil
	}
}

func checkExecutedCommands(expectedCommands []string, t *testing.T) {
	actualCommands := []string{}
	for i := 0; i < len(expectedCommands); i++ {
		actualCommands = append(actualCommands, <-commands)
	}
	for i, actualCommand := range actualCommands {
		expectedCommand := expectedCommands[i]
		if strings.Index(expectedCommand, "^") == 0 {
			if m, err := regexp.MatchString(expectedCommand, actualCommand); m == false || err != nil {
				t.Errorf("wrong commands were executed: %s == %s", expectedCommand, actualCommand)
			}
		} else if expectedCommand != actualCommand {
			t.Errorf("wrong commands were executed: %s != %s", expectedCommand, actualCommand)
		}
	}
}

func TestExecCmd(t *testing.T) {
	year := time.Now().Year()
	out, err := originalExecutor("date", "+%Y")
	if err != nil {
		t.Errorf("Failed to execute date command: %s", err)
	}
	actual := strings.TrimSpace(string(out))
	if strconv.Itoa(year) != actual {
		t.Errorf("year not match '%d' == '%s'", year, actual)
	}
}

func TestExecCmdOnTest(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	go ExecCmd("date", "+%Y")

	checkExecutedCommands([]string{
		"date +%Y",
	}, t)
}

func TestExecCmdWithTimeoutKillsTheCommand(t *testing.T) {
	start := time.Now()
	_, err := ExecCmdWithTimeout(200*time.Millisecond, "sleep", "5")

	if err == nil || !strings.Contains(err.Error(), "timed out after 200ms") {
		t.Errorf("expected a timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("command was not killed, took %s", elapsed)
	}
}

func TestTimedCommandExecutorKeepsTheOutputOfAFinishedCommand(t *testing.T) {
	out, err := timedCommandExecutor(5*time.Second, "sh", "-c", "echo done")

	if err != nil || strings.TrimSpace(string(out)) != "done" {
		t.Errorf("expected the output and no error, got %q, %v", out, err)
	}
}

func TestExecCmdWithTimeoutKeepsStderrOutOfTheOutput(t *testing.T) {
	out, err := ExecCmdWithTimeout(5*time.Second, "sh", "-c", "echo out; echo warning >&2")

	if err != nil || out != "out" {
		t.Errorf("expected only stdout, got %q, %v", out, err)
	}

	_, err = ExecCmdWithTimeout(5*time.Second, "sh", "-c", "echo broken >&2; exit 3")

	if err == nil || !strings.Contains(err.Error(), "exit status 3: broken") {
		t.Errorf("expected stderr in the error, got %v", err)
	}
}
