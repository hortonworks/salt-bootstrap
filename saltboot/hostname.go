package saltboot

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

const EXAMPLE_DOMAIN = "example.com"
const HOSTS_FILE = "/etc/hosts"
const NETWORK_SYSCONFIG_FILE = "/etc/sysconfig/network"
const NETWORK_SYSCONFIG_FILE_SUSE = "/etc/sysconfig/network/config"
const HOSTNAME_FILE = "/etc/hostname"

var readFile = ioutil.ReadFile
var writeFile = ioutil.WriteFile

func getFQDN() (string, error) {
	return ExecCmd("hostname", "-f")
}

func constructFQDN(hostName, domain string) string {
	var fqdn string
	if strings.Contains(hostName, domain) {
		fqdn = hostName
	} else {
		fqdn = hostName + "." + domain
	}
	return fqdn
}

func getShortHostName(hostName, domain string) string {
	return strings.TrimSuffix(hostName, "."+domain)
}

func getHostName() (string, error) {
	out, err := ExecCmd("hostname", "-s")
	if err != nil {
		log.Printf("[getHostName] hostname -s returned an error, fallback to simple hostname command, err: %s", err.Error())
		out, err = ExecCmd("hostname")
	}
	return out, err
}

func getDomain() (string, error) {
	return ExecCmd("hostname", "-d")
}

func setHostname(hostName string) (string, error) {
	return ExecCmd("hostname", hostName)
}

// This is required due to: https://github.com/saltstack/salt/issues/32719
func ensureHostIsResolvable(customHostname *string, customDomain string, ipv4address string, os *Os, cloud *Cloud) error {
	var hostName string
	if customHostname != nil && len(*customHostname) > 0 {
		log.Printf("[ensureHostIsResolvable] use custom hostname: %s", *customHostname)
		hostName = *customHostname
	} else {
		if hn, hostNameErr := getHostName(); hostNameErr != nil {
			return hostNameErr
		} else {
			log.Printf("[ensureHostIsResolvable] default hostName: %s", hn)
			hostName = hn
		}
	}

	var domain string
	if len(customDomain) > 0 {
		log.Printf("[ensureHostIsResolvable] use custom domain: %s", customDomain)
		domain = customDomain
	} else {
		if defaultDomain, domainError := getDomain(); domainError != nil || len(defaultDomain) == 0 {
			log.Printf("[ensureHostIsResolvable] default domain is not available")
			if isCloud(AZURE, cloud) {
				log.Printf("[ensureHostIsResolvable] cloud type is '%s', default domain is expected", cloud.Name)
				if domainError != nil {
					return domainError
				} else {
					return errors.New("it is expected to have a default domain, but it is empty")
				}
			} else {
				log.Printf("[ensureHostIsResolvable] use '%s' as default domain", EXAMPLE_DOMAIN)
				domain = EXAMPLE_DOMAIN
			}
		} else {
			log.Printf("[ensureHostIsResolvable] use default domain: %s", defaultDomain)
			domain = defaultDomain
		}
	}

	if err := updateHostsFile(hostName, domain, HOSTS_FILE, ipv4address); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update host file: %s", err.Error())
		return err
	}
	networkSysConfig := NETWORK_SYSCONFIG_FILE
	if isOs(os, SUSE, SLES12) {
		networkSysConfig = NETWORK_SYSCONFIG_FILE_SUSE
	}
	if err := updateSysConfig(hostName, domain, networkSysConfig); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update sys config: %s", err.Error())
		return err
	}
	if err := updateHostNameFile(hostName, HOSTNAME_FILE); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update host name: %s", err.Error())
		return err
	}
	return nil
}

func updateHostsFile(hostName, domain string, file string, ipv4address string) error {
	log.Printf("[updateHostsFile] hostName: %s, domain: %s, ip: %s", hostName, domain, ipv4address)
	b, err := readFile(file)
	if err != nil {
		return err
	}
	hostsFile := string(b)
	log.Printf("[updateHostsFile] original hosts file: %s", hostsFile)

	ipv4HostString := fmt.Sprintf("%s %s %s", ipv4address, constructFQDN(hostName, domain), getShortHostName(hostName, domain))
	log.Printf("[updateHostsFile] ipv4HostString: %s", ipv4HostString)

	lines := strings.Split(hostsFile, "\n")
	var filteredLines = make([]string, 0)
	for _, line := range lines {
		if !strings.Contains(line, ipv4address) {
			filteredLines = append(filteredLines, line)
		}
	}
	var hostsLines = append(filteredLines, ipv4HostString)
	hostsFile = strings.Join(hostsLines, "\n") + "\n"
	log.Printf("[updateHostsFile] updated hosts file: %s", hostsFile)
	err = writeFile(file, []byte(hostsFile), 0644)
	if err != nil {
		return err
	}

	_, err = setHostname(hostName)
	if err != nil {
		return err
	}

	return nil
}

func updateSysConfig(hostName, domain, file string) error {
	log.Printf("[updateSysConfig] hostname: %s, domain: %s", hostName, domain)
	b, err := readFile(file)
	if err != nil {
		return err
	}
	sysConfig := string(b)
	log.Printf("[updateSysConfig] original sysconfig %s: %s", file, sysConfig)

	lines := strings.Split(sysConfig, "\n")
	var filteredLines = make([]string, 0)
	for _, line := range lines {
		if !strings.Contains(line, "HOSTNAME=") && len(line) > 0 {
			filteredLines = append(filteredLines, line)
		}
	}

	hostNameString := "HOSTNAME=" + constructFQDN(hostName, domain)
	sysConfig = strings.Join(filteredLines, "\n") + "\n" + hostNameString
	log.Printf("[updateSysConfig] updated sysconfig %s: %s", file, sysConfig)
	err = writeFile(file, []byte(sysConfig), 0644)
	if err != nil {
		return err
	}
	return nil
}

func updateHostNameFile(hostName string, file string) error {
	log.Printf("[updateHostNameFile] hostname: %s, file: %s", hostName, file)
	err := writeFile(file, []byte(hostName), 0644)
	if err != nil {
		return err
	}
	return nil
}
