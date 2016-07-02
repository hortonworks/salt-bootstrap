package saltboot

import (
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
