package saltboot

import (
	"io/ioutil"
	"log"
	"strings"
)

const DEFAULT_DOMAIN = ".example.com"
const HOST_FILE_NAME = "/etc/hosts"

func getIpv4Address() (string, error) {
	return ExecCmd("hostname", "-i")
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
	updateIpv6HostName(hostname, domain)

	return nil
}

func updateIpv6HostName(hostName string, domain string) error {
	log.Printf("[updateIpv6HostName] hostName: %s, domain: %s", hostName, domain)
	b, err := ioutil.ReadFile(HOST_FILE_NAME)
	if err != nil {
		return err
	}
	hostfile := string(b)
	log.Printf("[updateIpv6HostName] original hostfile: %s", hostfile)
	address, err := getIpv4Address()
	if err != nil {
		return err
	}
	ipv6hostString := address + " " + hostName + domain + " " + hostName
	log.Printf("[updateIpv6HostName] ipv6hostString: %s", ipv6hostString)
	if !strings.Contains(hostfile, address) {
		hostfile = hostfile + "\n" + ipv6hostString
		log.Printf("[updateIpv6HostName] updated hostfile: %s", hostfile)
		err = ioutil.WriteFile(HOST_FILE_NAME, []byte(hostfile), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}
