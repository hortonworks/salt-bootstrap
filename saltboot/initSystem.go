package saltboot

import (
    "log"
    "os"
)

type InitSystem struct {
    Start           string
    Stop            string
    Enable          string
    Disable         string
    ActionBin       string
    StateBin        string
    CommandOrderASC bool
}

var (
    SYSYEM_D = InitSystem{ActionBin: "/bin/systemctl", StateBin: "/bin/systemctl", Start:"start", Stop:"stop", Enable:"enable", Disable:"disable", CommandOrderASC:true}
    SYS_V_INIT = InitSystem{ActionBin: "/sbin/service", StateBin: "/sbin/chkconfig", Start:"start", Stop:"stop", Enable:"on", Disable:"off", CommandOrderASC:false}
)

func (system InitSystem) ActionCommand(service string, run bool) []string {
    if run {
        if system.CommandOrderASC {
            return []string{system.ActionBin, system.Start, service}
        }
        return []string{system.ActionBin, service, system.Start}
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
    if _, err := os.Stat("/bin/systemctl"); err == nil {
        log.Printf("[GetInitSystem] /bin/systemctl found, assume systemd")
        return SYSYEM_D
    }
    log.Printf("[GetInitSystem] /bin/systemctl not found, assume sysv init")
    return SYS_V_INIT
}
