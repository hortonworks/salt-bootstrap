package cbboot

import (
    "log"
    "net"
    "os"
    "strconv"
    "strings"
)

func determineAddresses() (map[string]bool, error) {
    log.Printf("[getIps] getting all available addresses")

    ret := make(map[string]bool)

    addrs, err := net.InterfaceAddrs()

    for _, a := range addrs {
        if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                var ipv4 = ipnet.IP.String()
                log.Printf("[getIps] addr: %s", ipv4)
                ret[ipv4] = true
            }
        }
    }

    return ret, err
}

func determineBootstrapPort() (int) {

    portStr := os.Getenv("CBBOOT_PORT")
    log.Printf("[determineBootstrapPort] CBBOOT_PORT: %s", portStr)
    port, err := strconv.Atoi(portStr)
    if (err != nil) {
        port = 9090
        log.Printf("[determineBootstrapPort] using default port: %s", port)
    }

    return port
}

func determineAuthCredentials() (string, string) {
    username := os.Getenv("CBBOOT_USERNAME")
    password := os.Getenv("CBBOOT_PASSWORD")
    log.Printf("[determineAuthCredentials] CBBOOT_USERNAME: %s CBBOOT_PASSWORD: %s", username, password)

    if len(strings.TrimSpace(username)) == 0 || len(strings.TrimSpace(password)) == 0 {
        username = "cbadmin"
        password = "cbadmin"
        log.Printf("[determineAuthCredentials] using default credentials, username: %s, password: %s", username, password)
    }
    return username, password
}


