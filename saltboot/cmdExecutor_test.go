package saltboot

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func TestExecCmd(t *testing.T) {
	year := time.Now().Year()
	out, err := ExecCmd("date", "+%Y")
	if err != nil {
		t.Errorf("Failed to execute date command: %s", err)
	} else if strconv.Itoa(year) != out {
		t.Errorf("year != out %d == %s", year, out)
	}
}

func TestExecCmdOnTest(t *testing.T) {
	os.Setenv(ENV_TYPE, "test")
	defer os.Clearenv()

	out, err := ExecCmd("date", "+%Y")
	if out != "" || err != nil {
		t.Errorf("command was executed: %s - %s", out, err)
	}
	if os.Getenv(EXECUTED_COMMANDS) != "date +%Y:" {
		t.Errorf("wrong commands were executed: %s", os.Getenv(EXECUTED_COMMANDS))
	}
}
