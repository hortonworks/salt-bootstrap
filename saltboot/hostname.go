package saltboot

import (
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const DEFAULT_DOMAIN = ".example.com"
const HOST_FILE_NAME = "/etc/hosts"

func getIpv4Address() (string, error) {
	return ExecCmd("hostname", "-I")
}

func getFQDN() (string, error) {
	return ExecCmd("hostname", "-f")
}

func getHostName() (string, error) {
	return ExecCmd("hostname", "-s")
}

func getDomain() (string, error) {
	return ExecCmd("hostname", "-d")
}

// This is required due to: https://github.com/saltstack/salt/issues/32719
func ensureIpv6Resolvable(customDomain string) error {
	hostname, hostNameErr := getHostName()
	log.Printf("[ensureIpv6Resolvable] hostName: %s", hostname)
	if hostNameErr != nil {
		return hostNameErr
	}

	domain, domainError := getDomain()
	log.Printf("[ensureIpv6Resolvable] origin domain: %s", domain)
	if customDomain == "" {
		if domainError != nil || domain == "" {
			domain = DEFAULT_DOMAIN
		}
	} else {
		domain = customDomain
	}
	updateIpv6HostName(hostname, domain, HOST_FILE_NAME, getIpv4Address, ioutil.ReadFile, ioutil.WriteFile)

	return nil
}

func updateIpv6HostName(hostName string, domain string, file string,
	getIpv4Address func() (string, error),
	readFile func(filename string) ([]byte, error),
	writeFile func(filename string, data []byte, perm os.FileMode) error) error {
	log.Printf("[updateIpv6HostName] hostName: %s, domain: %s", hostName, domain)
	b, err := readFile(file)
	if err != nil {
		return err
	}
	hostsFile := string(b)
	log.Printf("[updateIpv6HostName] original hosts file: %s", hostsFile)
	address, err := getIpv4Address()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	ipv6hostString := address + " " + hostName + domain + " " + hostName
	log.Printf("[updateIpv6HostName] ipv6hostString: %s", ipv6hostString)

	lines := strings.Split(hostsFile, "\n")
	var filteredLines = make([]string, 0)
	for _, line := range lines {
		if !strings.Contains(line, address) {
			filteredLines = append(filteredLines, line)
		}
	}
	hostsFile = strings.Join(filteredLines, "\n") + "\n" + ipv6hostString
	log.Printf("[updateIpv6HostName] updated hosts file: %s", hostsFile)
	err = writeFile(file, []byte(hostsFile), 0644)
	if err != nil {
		return err
	}

	return nil
}
