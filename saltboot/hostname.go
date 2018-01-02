package saltboot

import (
	"io/ioutil"
	"log"
	"strings"
)

const EXAMPLE_DOMAIN = ".example.com"
const HOSTS_FILE = "/etc/hosts"
const NETWORK_SYSCONFIG_FILE = "/etc/sysconfig/network"
const HOSTNAME_FILE = "/etc/hostname"

var readFile = ioutil.ReadFile
var writeFile = ioutil.WriteFile

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

func setHostname(hostName string) (string, error) {
	return ExecCmd("hostname", hostName)
}

// This is required due to: https://github.com/saltstack/salt/issues/32719
func ensureHostIsResolvable(customHostname *string, customDomain string) error {
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
			log.Printf("[ensureHostIsResolvable] default domain is not available, use: %s", EXAMPLE_DOMAIN)
			domain = EXAMPLE_DOMAIN
		} else {
			log.Printf("[ensureHostIsResolvable] use default domain: %s", defaultDomain)
			domain = defaultDomain
		}
	}

	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	if err := updateHostsFile(hostName, domain, HOSTS_FILE, getIpv4Address); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update host file: %s", err.Error())
		return err
	}
	if err := updateSysConfig(hostName, domain, NETWORK_SYSCONFIG_FILE); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update sys config: %s", err.Error())
		return err
	}
	if err := updateHostNameFile(hostName, HOSTNAME_FILE); err != nil {
		log.Printf("[ensureHostIsResolvable] [ERROR] unable to update host name: %s", err.Error())
		return err
	}
	return nil
}

func updateHostsFile(hostName string, domain string, file string, getIpv4Address func() (string, error)) error {
	ip, err := getIpv4Address()
	if err != nil {
		return err
	}

	log.Printf("[updateHostsFile] hostName: %s, domain: %s, ip: %s", hostName, domain, ip)
	b, err := readFile(file)
	if err != nil {
		return err
	}
	hostsFile := string(b)
	log.Printf("[updateHostsFile] original hosts file: %s", hostsFile)

	ipv4HostString := ip + " " + hostName + domain + " " + hostName
	log.Printf("[updateHostsFile] ipv4HostString: %s", ipv4HostString)

	lines := strings.Split(hostsFile, "\n")
	var filteredLines = make([]string, 0)
	for _, line := range lines {
		if !strings.Contains(line, ip) {
			filteredLines = append(filteredLines, line)
		}
	}
	hostsFile = strings.Join(filteredLines, "\n") + "\n" + ipv4HostString
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

func updateSysConfig(hostName string, domain string, file string) error {
	log.Printf("[updateSysConfig] hostname: %s, domain: %s", hostName, domain)
	b, err := readFile(file)
	if err != nil {
		return err
	}
	sysConfig := string(b)
	log.Printf("[updateSysConfig] original sysconfig: %s", sysConfig)

	lines := strings.Split(sysConfig, "\n")
	var filteredLines = make([]string, 0)
	for _, line := range lines {
		if !strings.Contains(line, "HOSTNAME=") && len(line) > 0 {
			filteredLines = append(filteredLines, line)
		}
	}

	hostNameString := "HOSTNAME=" + hostName + domain
	sysConfig = strings.Join(filteredLines, "\n") + "\n" + hostNameString
	log.Printf("[updateSysConfig] updated sysconfig: %s", sysConfig)
	err = writeFile(file, []byte(sysConfig), 0644)
	if err != nil {
		return err
	}

	return nil
}

func updateHostNameFile(hostName string, file string) error {
	log.Printf("[updateHostNameFile] hostname: %s", hostName)
	err := writeFile(file, []byte(hostName), 0644)
	if err != nil {
		return err
	}

	return nil
}
