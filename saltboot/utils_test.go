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

func TestMapStringToUint16(t *testing.T) {
	// Example function to test the mapping
	fn := func(s string) uint16 {
		return uint16(len(s))
	}

	tests := []struct {
		input    []string
		expected []uint16
	}{
		{[]string{"a", "ab", "abc"}, []uint16{0x01, 0x02, 0x03}},
		{[]string{"", "hello", "world"}, []uint16{0x00, 0x05, 0x05}},
		{[]string{}, []uint16{}},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result := MapStringToUint16(test.input, fn)
			if !EqualUint16Slices(result, test.expected) {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}

func TestMapUint16ToString(t *testing.T) {
	// Example function to test the mapping
	fn := func(u uint16) string {
		return string(rune(u))
	}

	tests := []struct {
		input    []uint16
		expected []string
	}{
		{[]uint16{0x41, 0x42, 0x43}, []string{"A", "B", "C"}},
		{[]uint16{0x30, 0x31, 0x32}, []string{"0", "1", "2"}},
		{[]uint16{0x61, 0x62, 0x63}, []string{"a", "b", "c"}},
		{[]uint16{}, []string{}},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result := MapUint16ToString(test.input, fn)
			if !EqualStringSlices(result, test.expected) {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}

func TestEqualUint16Slices(t *testing.T) {
	tests := []struct {
		s1, s2   []uint16
		expected bool
	}{
		{[]uint16{0x01, 0x02, 0x03}, []uint16{0x01, 0x02, 0x03}, true},
		{[]uint16{0x01, 0x02, 0x03}, []uint16{0x03, 0x02, 0x01}, false},
		{[]uint16{0x01, 0x02, 0x03}, []uint16{0x01, 0x02}, false},
		{[]uint16{}, []uint16{}, true},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result := EqualUint16Slices(test.s1, test.s2)
			if result != test.expected {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		s1, s2   []string
		expected bool
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"a", "b", "c"}, []string{"a", "b"}, false},
		{[]string{"a", "b", "c"}, []string{"a", "c", "b"}, false},
		{[]string{"apple", "banana"}, []string{"apple", "banana"}, true},
		{[]string{"apple", "banana"}, []string{"apple", "orange"}, false},
		{[]string{}, []string{}, true},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result := EqualStringSlices(test.s1, test.s2)
			if result != test.expected {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}
