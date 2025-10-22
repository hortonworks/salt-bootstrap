package saltboot

import (
	"os"
	"testing"
)

func TestWriteToFile(t *testing.T) {
	tempDirName, _ := os.MkdirTemp("", "writepillartest")
	defer os.RemoveAll(tempDirName)

	list := make([]Server, 0)
	list = append(list, Server{Name: "name", Address: "address"})
	list = append(list, Server{Name: "name2", Address: "address2"})
	servers := Servers{
		Path:    tempDirName + "servers",
		Servers: list,
	}

	_, err := servers.WriteToFile()

	if err != nil {
		t.Errorf("error occurred during write %s", err)
	}

	expected := "\naddress name\naddress2 name2"
	content, _ := os.ReadFile(tempDirName + "servers")
	if string(content) != expected {
		t.Errorf("servers content not match %s == %s", expected, string(content))
	}
}
