package saltboot

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestActionCommandRunCommandOrderASC(t *testing.T) {
	s := InitSystem{
		ActionBin:       "bin",
		Start:           "start",
		CommandOrderASC: true,
	}

	resp := s.ActionCommand("service", START_ACTION)

	expected := []string{"bin", "start", "service"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestActionCommandRunCommandOrderDESC(t *testing.T) {
	s := InitSystem{
		ActionBin:       "bin",
		Start:           "start",
		CommandOrderASC: false,
	}

	resp := s.ActionCommand("service", START_ACTION)

	expected := []string{"bin", "service", "start"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestActionCommandCommandOrderASC(t *testing.T) {
	s := InitSystem{
		ActionBin:       "bin",
		Stop:            "stop",
		CommandOrderASC: true,
	}

	resp := s.ActionCommand("service", STOP_ACTION)

	expected := []string{"bin", "stop", "service"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestActionCommandCommandOrderDESC(t *testing.T) {
	s := InitSystem{
		ActionBin:       "bin",
		Stop:            "stop",
		CommandOrderASC: false,
	}

	resp := s.ActionCommand("service", STOP_ACTION)

	expected := []string{"bin", "service", "stop"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestStateCommandRunCommandOrderASC(t *testing.T) {
	s := InitSystem{
		StateBin:        "bin",
		Enable:          "enable",
		CommandOrderASC: true,
	}

	resp := s.StateCommand("service", true)

	expected := []string{"bin", "enable", "service"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestStateCommandRunCommandOrderDESC(t *testing.T) {
	s := InitSystem{
		StateBin:        "bin",
		Enable:          "enable",
		CommandOrderASC: false,
	}

	resp := s.StateCommand("service", true)

	expected := []string{"bin", "service", "enable"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestStateCommandCommandOrderASC(t *testing.T) {
	s := InitSystem{
		StateBin:        "bin",
		Disable:         "disable",
		CommandOrderASC: true,
	}

	resp := s.StateCommand("service", false)

	expected := []string{"bin", "disable", "service"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestStateCommandCommandOrderDESC(t *testing.T) {
	s := InitSystem{
		StateBin:        "bin",
		Disable:         "disable",
		CommandOrderASC: false,
	}

	resp := s.StateCommand("service", false)

	expected := []string{"bin", "service", "disable"}
	if strings.Join(resp, "") != strings.Join(expected, "") {
		t.Errorf("order not match %s == %s", expected, resp)
	}
}

func TestGetInitSystemSystemD(t *testing.T) {
	stat := func(name string) (os.FileInfo, error) {
		return nil, nil
	}

	resp := GetInitSystem(stat)

	if resp != SYSTEM_D {
		t.Errorf("wrong init system found %s == %s", SYSTEM_D, resp)
	}
}

func TestGetInitSystemSystemV(t *testing.T) {
	stat := func(name string) (os.FileInfo, error) {
		return nil, errors.New("file not found")
	}

	resp := GetInitSystem(stat)

	if resp != SYS_V_INIT {
		t.Errorf("wrong init system found %s == %s", SYS_V_INIT, resp)
	}
}
