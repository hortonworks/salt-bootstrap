package saltboot

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"
)

const (
	dirName     = "test"
	fileName    = "test.txt"
	zipName     = "test.zip"
	testContent = "test content"
)

func TestUnzipSimpleFileSuccess(t *testing.T) {
	executeTest(t, fileName)
}

func TestUnzipFileWithDirectorySuccess(t *testing.T) {
	executeTest(t, filepath.Join(dirName, fileName))
}

func executeTest(t *testing.T, file string) {
	tempDirName, _ := ioutil.TempDir("", "unziptest")
	func() {
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)
		defer zipWriter.Close()
		testBytes := []byte(testContent)
		zipEntry, _ := zipWriter.Create(file)
		zipEntry.Write(testBytes)
		zipWriter.Close()
		zipFileName := filepath.Join(tempDirName, zipName)
		ioutil.WriteFile(zipFileName, buf.Bytes(), 0600)

		err := Unzip(zipFileName, tempDirName)
		if err != nil {
			t.Errorf("Unable to decompress archive '%s'", err)
			return
		}

		testFileName := filepath.Join(tempDirName, file)
		content, err := ioutil.ReadFile(testFileName)
		if err != nil {
			t.Errorf("Failed to read back decompressed file '%s' because '%s'", file, err)
		} else if !bytes.Equal(content, testBytes) {
			t.Errorf("Decompressed content doesn't match '%s' == '%s'", string(testBytes), string(content))
		}
	}()
}
