package saltboot

import (
	"io/fs"
	"os"
)

func WriteFile(filename string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err2 := f.Write(data)
	if err2 != nil {
		return err2
	}
	err3 := f.Sync()
	if err3 != nil {
		return err3
	}
	err4 := f.Close()
	if err4 != nil {
		return err4
	}
	return nil
}
