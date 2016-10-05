package saltboot

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestWriteToFile(t *testing.T) {
	tempDirName, _ := ioutil.TempDir("", "writepillartest")
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
		t.Errorf("error occured during write %s", err)
	}

	expected := "\naddress name\naddress2 name2"
	content, _ := ioutil.ReadFile(tempDirName + "servers")
	if string(content) != expected {
		t.Errorf("servers content not match %s == %s", expected, string(content))
	}
}
