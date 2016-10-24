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

func getHostName() (string, error) {
	return ExecCmd("hostname", "-f")
}

// This is required due to: https://github.com/saltstack/salt/issues/32719
func ensureIpv6Resolvable(domain string) error {
	fqdn, err := getHostName()
	log.Printf("[ensureIpv6Resolvable] fqdn: %s", fqdn)
	if err != nil {
		return err
	}
	if !strings.Contains(fqdn, ".") {
		// only fqdn does not contain domain
		if domain != "" {
			updateIpv6HostName(fqdn, domain)
		} else {
			//if there is no domain, we need to add one since ambari fails without domain, actually it does nothing just hangs..
			updateIpv6HostName(fqdn, DEFAULT_DOMAIN)
		}
	} else {
		if domain != "" {
			hostName := strings.Split(fqdn, ".")[0]
			updateIpv6HostName(hostName, domain)
		}
	}

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
