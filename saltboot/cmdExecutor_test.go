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
			t.Errorf("wrong commands were executed: %s == %s", expectedCommand, actualCommand)
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
