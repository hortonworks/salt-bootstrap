package saltboot

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer closeIt(r)

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer closeIt(rc)

		var path string
		if f.FileInfo().IsDir() {
			path = filepath.Join(dest, f.Name)
			if err := os.MkdirAll(path, f.Mode()); err != nil {
				return err
			}
		} else {
			if strings.ContainsRune(f.Name, os.PathSeparator) {
				last := strings.LastIndex(f.Name, string(os.PathSeparator))
				dirs := f.Name[0:last]
				name := f.Name[last+1 : len(f.Name)]
				if err := os.MkdirAll(filepath.Join(dest, dirs), 0744); err != nil {
					return err
				}
				path = filepath.Join(dest, dirs, name)
			} else {
				path = filepath.Join(dest, f.Name)
			}
			f, err := os.OpenFile(
				path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer closeIt(f)

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
