package saltboot

import (
	"os"
	"testing"
)

func TestHostsFileWriteRemoveExistingIp(t *testing.T) {
	getIpv4Address := func() (string, error) {
		return "10.0.0.1", nil
	}

	readFile := func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1`
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	updateIpv6HostName("hostname-1", "example.com", "hosts", getIpv4Address, readFile, writeFile)

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.example.com hostname-1`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteRemoveExistingIpNotLastLine(t *testing.T) {
	getIpv4Address := func() (string, error) {
		return "10.0.0.1", nil
	}

	readFile := func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.2 hostname-2.compute.internal hostname-2`
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	updateIpv6HostName("hostname-1", "example.com", "hosts", getIpv4Address, readFile, writeFile)

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.1 hostname-1.example.com hostname-1`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteRemoveExistingIpMiddleLastLine(t *testing.T) {
	getIpv4Address := func() (string, error) {
		return "10.0.0.1", nil
	}

	readFile := func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.3 hostname-3.compute.internal hostname-3`
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	updateIpv6HostName("hostname-1", "example.com", "hosts", getIpv4Address, readFile, writeFile)

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3
10.0.0.1 hostname-1.example.com hostname-1`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteIpNotPresent(t *testing.T) {
	getIpv4Address := func() (string, error) {
		return "10.0.0.1", nil
	}

	readFile := func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2
10.0.0.3 hostname-3`
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	updateIpv6HostName("hostname-1", "example.com", "hosts", getIpv4Address, readFile, writeFile)

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2
10.0.0.3 hostname-3
10.0.0.1 hostname-1.example.com hostname-1`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteExistingWithDefaultDomain(t *testing.T) {
	getIpv4Address := func() (string, error) {
		return "10.0.0.1", nil
	}

	readFile := func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3`
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	updateIpv6HostName("hostname-1", ".compute.internal", "hosts", getIpv4Address, readFile, writeFile)

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3
10.0.0.1 hostname-1.compute.internal hostname-1`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}
