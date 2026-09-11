package saltboot

import (
	"os"
	"testing"
)

var emptyReadFile = func(filename string) ([]byte, error) {
	return make([]byte, 0), nil
}
var emptyWriteFile = func(filename string, data []byte, perm os.FileMode) error {
	return nil
}

func init() {
	readFile = emptyReadFile
	writeFile = emptyWriteFile
}

func TestHostsFileWriteRemoveExistingIp(t *testing.T) {
	readFile = func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1
`
		return []byte(hostsFile), nil
	}
	defer func() {
		readFile = emptyReadFile
	}()

	var result string
	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}
	defer func() {
		writeFile = emptyWriteFile
	}()

	updateHostsFile("hostname-1.example.com", "example.com", "hosts", "10.0.0.1")

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost

10.0.0.1 hostname-1.example.com hostname-1
`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteRemoveExistingIpNotLastLine(t *testing.T) {
	readFile = func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.2 hostname-2.compute.internal hostname-2
`
		return []byte(hostsFile), nil
	}
	defer func() {
		readFile = emptyReadFile
	}()

	var result string
	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}
	defer func() {
		writeFile = emptyWriteFile
	}()

	updateHostsFile("hostname-1", "example.com", "hosts", "10.0.0.1")

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2

10.0.0.1 hostname-1.example.com hostname-1
`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteRemoveExistingIpMiddleLastLine(t *testing.T) {
	readFile = func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.3 hostname-3.compute.internal hostname-3
`
		return []byte(hostsFile), nil
	}
	defer func() {
		readFile = emptyReadFile
	}()

	var result string
	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}
	defer func() {
		writeFile = emptyWriteFile
	}()

	updateHostsFile("hostname-1", "example.com", "hosts", "10.0.0.1")

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3

10.0.0.1 hostname-1.example.com hostname-1
`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteIpNotPresent(t *testing.T) {
	readFile = func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2
10.0.0.3 hostname-3
`
		return []byte(hostsFile), nil
	}
	defer func() {
		readFile = emptyReadFile
	}()

	var result string
	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}
	defer func() {
		writeFile = emptyWriteFile
	}()

	updateHostsFile("hostname-1", "example.com", "hosts", "10.0.0.1")

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2
10.0.0.3 hostname-3

10.0.0.1 hostname-1.example.com hostname-1
`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestHostsFileWriteExistingWithDefaultDomain(t *testing.T) {
	readFile = func(filename string) ([]byte, error) {
		hostsFile := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.1 hostname-1.compute.internal hostname-1
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3
`
		return []byte(hostsFile), nil
	}
	defer func() {
		readFile = emptyReadFile
	}()

	var result string
	writeFile = func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}
	defer func() {
		writeFile = emptyWriteFile
	}()

	updateHostsFile("hostname-1", "compute.internal", "hosts", "10.0.0.1")

	expected := `
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
10.0.0.2 hostname-2.compute.internal hostname-2
10.0.0.3 hostname-3.compute.internal hostname-3

10.0.0.1 hostname-1.compute.internal hostname-1
`

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}
}

func TestEnsureHostIsResolvableReturnsFQDN(t *testing.T) {
	host := "host-1"
	fqdn, err := ensureHostIsResolvable(&host, "example.com", "10.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if fqdn != "host-1.example.com" {
		t.Errorf("expected fqdn host-1.example.com, got %q", fqdn)
	}
}

func TestCreateFQDN(t *testing.T) {
	fqdn := constructFQDN("hostname-1.example.com", "example.com")
	if fqdn != "hostname-1.example.com" {
		t.Errorf("fqdn does not match, expected: %s, got: %s", "hostname-1.example.com", fqdn)
	}

	fqdn = constructFQDN("hostname-2", "example.com")
	if fqdn != "hostname-2.example.com" {
		t.Errorf("fqdn does not match, expected: %s, got: %s", "hostname-2.example.com", fqdn)
	}
}

func TestConstructFQDNAppendsDomainWhenHostnameMerelyContainsIt(t *testing.T) {
	// "myexample.com-1" contains "example.com" as a substring but is not in the
	// domain, so the domain must still be appended.
	fqdn := constructFQDN("myexample.com-1", "example.com")
	if fqdn != "myexample.com-1.example.com" {
		t.Errorf("fqdn does not match, expected: %s, got: %s", "myexample.com-1.example.com", fqdn)
	}

	// A host whose name equals the domain is already fully qualified.
	fqdn = constructFQDN("example.com", "example.com")
	if fqdn != "example.com" {
		t.Errorf("fqdn does not match, expected: %s, got: %s", "example.com", fqdn)
	}
}

func TestGetShortHostName(t *testing.T) {
	hostName := getShortHostName("hostname-1.example.com", "example.com")
	if hostName != "hostname-1" {
		t.Errorf("hostName does not match, expected: %s, got: %s", "hostname-1", hostName)
	}

	hostName = getShortHostName("hostname-1", "example.com")
	if hostName != "hostname-1" {
		t.Errorf("hostName does not match, expected: %s, got: %s", "hostname-1", hostName)
	}

}
