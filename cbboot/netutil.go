package cbboot

import (
    "log"
    "net"


    "os"
    "strconv")


func determineAddresses() (map[string]bool, error) {
    log.Println("[getIps] getting all available addresses")

    ret := make(map[string]bool)

    addrs, err := net.InterfaceAddrs()

    for _, a := range addrs {
        if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                var ipv4 = ipnet.IP.String()
                log.Println("[getIps] addr: ", ipv4)
                ret[ipv4] = true
            }
        }
    }

    return ret, err
}

func determineBootstrapPort() (int) {

    portStr := os.Getenv("CBBOOT_PORT")
    log.Println("[determineBootstrapPort] CBBOOT_PORT:", portStr)
    port, err := strconv.Atoi(portStr)
    if(err != nil) {
        port = 9090
        log.Println("[determineBootstrapPort] using default port:", port)
    }

    return port
}


