package saltboot

import "testing"

func TestIsOsWhenOsIsNotProvided(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	go isOs(nil, DEBIAN)

	checkExecutedCommands([]string{
		"grep Debian /etc/issue",
	}, t)
}

func TestIsOsWhenOsIsEmptyString(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	go isOs(&Os{Name: ""}, DEBIAN)

	checkExecutedCommands([]string{
		"grep Debian /etc/issue",
	}, t)
}

func TestIsOsWhenOsIsNotProvidedForSuse(t *testing.T) {
	watchCommands = true
	defer func() { watchCommands = false }()

	go isOs(nil, SUSE, SLES12)

	checkExecutedCommands([]string{
		"grep SUSE /etc/issue",
		"grep sles12 /etc/issue",
	}, t)
}

func TestIsOsWhenDebianIsProvided(t *testing.T) {
	match := isOs(&Os{Name: "debian9"}, DEBIAN)

	if !match {
		t.Error("debian is expected to be found")
	}
}

func TestIsOsWhenUbuntuIsProvided(t *testing.T) {
	match := isOs(&Os{Name: "ubuntu16"}, UBUNTU)

	if !match {
		t.Error("ubuntu is expected to be found")
	}
}

func TestIsOsWhenSuseIsProvided(t *testing.T) {
	match := isOs(&Os{Name: "sles12sp3"}, SUSE, SLES12)

	if !match {
		t.Error("suse is expected to be found")
	}
}

func TestIsOsWhenAmazonlinux2IsProvided(t *testing.T) {
	match := isOs(&Os{Name: "amazonlinux2"}, AMAZONLINUX_2)

	if !match {
		t.Error("amazonlinux2 is expected to be found")
	}
}

func TestIsCloudForNilInut(t *testing.T) {
	match := isCloud(AZURE, nil)
	if match {
		t.Error("isCloud should return false for nil input")
	}
}

func TestIsCloudForAzureInput(t *testing.T) {
	match := isCloud(AZURE, &Cloud{Name: "AZURE"})
	if !match {
		t.Error("isCloud should return true for AZURE input")
	}
}
