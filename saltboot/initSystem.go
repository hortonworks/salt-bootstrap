package saltboot

import (
	"log"
	"os"
)

type InitSystem struct {
	Start           string
	Stop            string
	Restart         string
	Enable          string
	Disable         string
	ActionBin       string
	StateBin        string
	CommandOrderASC bool
}

const (
	START_ACTION   = "start"
	STOP_ACTION    = "stop"
	RESTART_ACTION = "restart"
)

var stat = os.Stat

var (
	SYSTEM_D   = InitSystem{ActionBin: "/bin/systemctl", StateBin: "/bin/systemctl", Start: START_ACTION, Stop: STOP_ACTION, Restart: RESTART_ACTION, Enable: "enable", Disable: "disable", CommandOrderASC: true}
	SYS_V_INIT = InitSystem{ActionBin: "/sbin/service", StateBin: "/sbin/chkconfig", Start: START_ACTION, Stop: STOP_ACTION, Restart: RESTART_ACTION, Enable: "on", Disable: "off", CommandOrderASC: false}
)

func (system InitSystem) ActionCommand(service string, action string) []string {
	if action == START_ACTION || action == RESTART_ACTION {
		if action == START_ACTION {
			if system.CommandOrderASC {
				return []string{system.ActionBin, system.Start, service}
			}
			return []string{system.ActionBin, service, system.Start}
		}
		if system.CommandOrderASC {
			return []string{system.ActionBin, system.Restart, service}
		}
		return []string{system.ActionBin, service, system.Restart}
	}
	if system.CommandOrderASC {
		return []string{system.ActionBin, system.Stop, service}
	}
	return []string{system.ActionBin, service, system.Stop}
}

func (system InitSystem) StateCommand(service string, enable bool) []string {
	if enable {
		if system.CommandOrderASC {
			return []string{system.StateBin, system.Enable, service}
		}
		return []string{system.StateBin, service, system.Enable}
	}
	if system.CommandOrderASC {
		return []string{system.StateBin, system.Disable, service}
	}
	return []string{system.StateBin, service, system.Disable}
}

func (system InitSystem) Error() string {
	return "Failed to determine init system"
}

func GetInitSystem() (system InitSystem) {
	if _, err := stat("/bin/systemctl"); err == nil {
		log.Println("[GetInitSystem] /bin/systemctl found, assume systemd")
		return SYSTEM_D
	}
	log.Println("[GetInitSystem] /bin/systemctl not found, assume sysv init")
	return SYS_V_INIT
}
