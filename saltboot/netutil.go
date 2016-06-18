package saltboot

import (
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func DetermineDNSRecursors(fallbackDNSRecursors []string) []string {
	var dnsRecursors []string
	if dat, err := ioutil.ReadFile("/etc/resolv.conf"); err == nil {
		resolvContent := string(dat)
		log.Printf("[determineDNSRecursors] Loaded /etc/resolv.conf file: %s.", resolvContent)
		r, _ := regexp.Compile("nameserver .*")
		if nameserverLines := r.FindAllString(resolvContent, -1); nameserverLines != nil {
			for _, nameserverLine := range nameserverLines {
				log.Printf("[determineDNSRecursors] Found nameserverline: %s.", nameserverLine)
				dnsRecursor := strings.TrimSpace(strings.Split(nameserverLine, " ")[1])
				log.Printf("[determineDNSRecursors] Parsed DNS recursor: %s.", dnsRecursor)
				if !strings.Contains(dnsRecursor, "127.0.0.1") {
					dnsRecursors = append(dnsRecursors, dnsRecursor)
				}
			}
		}
	} else {
		log.Printf("[containerhandler] Failed to load /etc/resolv.conf")
	}
	if fallbackDNSRecursors != nil {
		dnsRecursors = append(dnsRecursors, fallbackDNSRecursors...)
	}
	return dnsRecursors
}

func DetermineBootstrapPort() int {

	portStr := os.Getenv("SALTBOOT_PORT")
	log.Printf("[determineBootstrapPort] SALTBOOT_PORT: %s", portStr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 7070
		log.Printf("[determineBootstrapPort] using default port: %d", port)
	}

	return port
}

func DetermineAuthCredentials() (string, string) {
	username := os.Getenv("SALTBOOT_USERNAME")
	password := os.Getenv("SALTBOOT_PASSWORD")
	log.Printf("[determineAuthCredentials] SALTBOOT_USERNAME: %s SALTBOOT_PASSWORD: %s", username, password)

	if len(strings.TrimSpace(username)) == 0 || len(strings.TrimSpace(password)) == 0 {
		username = "cbadmin"
		password = "cbadmin"
		log.Printf("[determineAuthCredentials] using default credentials, username: %s, password: %s", username, password)
	}
	return username, password
}
