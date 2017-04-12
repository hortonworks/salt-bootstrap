package cautils

import "testing"

func TestDetermineCaRootDirDefaultsProperly(t *testing.T) {
	getEmptyEnv := func(dirname string) string {
		return ""
	}

	rootDir := DetermineCaRootDir(getEmptyEnv)
	if rootDir != defaultCaLoc {
		t.Errorf("DetermineCaRootDir failed to fall back to default value %s != %s", rootDir, defaultCaLoc)
	}
}

func TestDetermineCaRootDirDetectsEnvProperly(t *testing.T) {
	getEnv := func(dirname string) string {
		return "mockmock"
	}

	rootDir := DetermineCaRootDir(getEnv)
	if rootDir != "mockmock" {
		t.Errorf("DetermineCaRootDir failed to fall back to default value %s != %s", rootDir, "mockmock")
	}
}

func TestDetermineCrtDirDefaultsProperly(t *testing.T) {
	getEmptyEnv := func(dirname string) string {
		return ""
	}

	rootDir := DetermineCrtDir(getEmptyEnv)
	if rootDir != defaultCrtLoc {
		t.Errorf("DetermineCaRootDir failed to fall back to default value %s != %s", rootDir, defaultCaLoc)
	}
}

func TestDetermineCrtDirDetectsEnvProperly(t *testing.T) {
	getEnv := func(dirname string) string {
		return "mockmock"
	}

	rootDir := DetermineCrtDir(getEnv)
	if rootDir != "mockmock" {
		t.Errorf("DetermineCaRootDir failed to fall back to default value %s != %s", rootDir, "mockmock")
	}
}
