package saltboot

import (
	"log"
	"strings"
)

const (
	UBUNTU        = "Ubuntu"
	DEBIAN        = "Debian"
	SUSE          = "SUSE"
	SLES12        = "sles12"
	AMAZONLINUX_2 = "amazonlinux2"
	AZURE         = "AZURE"
)

type closable interface {
	Close() error
}

func closeIt(target closable) {
	if err := target.Close(); err != nil {
		log.Printf("[Utils] [ERROR] couldn't close target: %s", err.Error())
	}
}

func isOs(os *Os, name ...string) bool {
	match := false
	for _, n := range name {
		if os == nil {
			match = isOsMatch(n)
		} else {
			match = containsLowerCase(os.Name, n)
		}
		if match {
			break
		}
	}
	return match
}

// Deprecated: Do not use this function, OS type is expected to be provided
func isOsMatch(os string) bool {
	out, _ := ExecCmd("grep", os, "/etc/issue")
	if len(out) > 0 {
		log.Printf("[isOsMatch] host OS is determined to be %s", os)
		return true
	}
	return false
}

func containsLowerCase(name, substr string) bool {
	return strings.Contains(strings.ToLower(name), strings.ToLower(substr))
}

func isCloud(name string, cloud *Cloud) bool {
	return cloud != nil && strings.ToLower(cloud.Name) == strings.ToLower(name)
}
