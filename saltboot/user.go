package saltboot

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"strings"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

const (
	SALT_USER               = "saltuser"
	SHADOW_FILE             = "/etc/shadow"
	SHADOW_FILE_BACKUP      = "/etc/shadow.backup"
	SHADOW_FILE_NEW         = "/etc/shadow.new"
	SHADOW_FILE_PERMISSIONS = 0640
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randStringRunes(n int) string {
	LETTER_RUNES := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = LETTER_RUNES[rand.Intn(len(LETTER_RUNES))]
	}
	return string(b)
}

func CreateUser(saltMaster SaltMaster, os *Os) (resp model.Response, err error) {
	log.Printf("[CreateUser] execute salt run request")

	result := "Create user: OK"

	// saltUser, _ := user.Lookup(SALT_USER) //requires cgo
	out, err := ExecCmd("grep", SALT_USER, "/etc/passwd")

	if len(out) == 0 || err != nil {
		log.Printf("[CreateUser] user: %s does not exsist and will be created", SALT_USER)

		hash, err := generatePasswordHash(saltMaster.Auth.Password)
		if err != nil {
			return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
		}

		if shouldUseUserAdd(os) {
			result, err = ExecCmd("groupadd", "-r", "wheel")
			if err != nil && strings.Contains(err.Error(), "exit status 9") {
				log.Printf("[CreateUser] ignore group exists error: %s", err.Error())
				err = nil
			}
			if err == nil {
				result, err = ExecCmd("useradd", "--no-create-home", "-G", "wheel", "-s", "/sbin/nologin", "--password", hash, SALT_USER)
			}
		} else {
			log.Printf("[CreateUser] host OS is determined to be Redhat based")
			result, err = ExecCmd("adduser", "--no-create-home", "-G", "wheel", "-s", "/sbin/nologin", "--password", hash, SALT_USER)
		}

		if err != nil {
			return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
		}
	} else {
		log.Printf("[CreateUser] user: %s exists, setting its password", SALT_USER)
		_, err = ChangeUserPassword(saltMaster)
		if err != nil {
			log.Printf("[CreateUser] ChangeUserPassword failed with error: %s", err.Error())
		}
	}

	resp = model.Response{Status: result, StatusCode: http.StatusOK}
	return resp, nil
}

func generatePasswordHash(password string) (string, error) {
	// Password needs to be "salted" and must start with this prefix for SHA512 encryption
	salt := "$6$" + randStringRunes(20)
	return generatePasswordHashWithSalt(password, salt)
}

func generatePasswordHashWithSalt(password string, salt string) (string, error) {
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(password), []byte(salt))
	if err != nil {
		return "", err
	}
	return hash, nil
}

func shouldUseUserAdd(os *Os) bool {
	return isOs(os, UBUNTU) || isOs(os, DEBIAN) || isOs(os, SUSE, SLES12)
}

func ChangeUserPassword(saltMaster SaltMaster) (resp model.Response, err error) {
	log.Printf("[ChangeUserPassword] execute salt run request")

	newPasswordHash, err := generatePasswordHash(saltMaster.Auth.Password)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to generate password hash", err)
	}

	shadowFileContents, err := readFile(SHADOW_FILE)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to read "+SHADOW_FILE, err)
	}

	shadowFileLines := strings.Split(string(shadowFileContents), "\n")
	oldPasswordHash := ""
	for i, shadowFileLine := range shadowFileLines {
		if strings.HasPrefix(shadowFileLine, SALT_USER+":") {
			oldPasswordHash = strings.Split(shadowFileLine, ":")[1]
			shadowFileLines[i] = strings.Replace(shadowFileLine, oldPasswordHash, newPasswordHash, 1)
			break
		}
	}

	if oldPasswordHash == "" {
		return errorResponse("[ChangeUserPassword] Could not find user "+SALT_USER+" in "+SHADOW_FILE, nil)
	}
	oldPasswordSalt := strings.Join(strings.SplitN(oldPasswordHash, "$", 2), "$")
	newPasswordHashWithOldSalt, err := generatePasswordHashWithSalt(saltMaster.Auth.Password, oldPasswordSalt)
	if err == nil && oldPasswordHash == newPasswordHashWithOldSalt {
		log.Println("[ChangeUserPassword] old and new passwords are the same")
		return model.Response{StatusCode: http.StatusOK}, nil
	}

	_, err = ExecCmd("cp", SHADOW_FILE, SHADOW_FILE_BACKUP)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to backup "+SHADOW_FILE+" to "+SHADOW_FILE_BACKUP, err)
	}

	newShadowFileContent := strings.Join(shadowFileLines, "\n")
	err = writeFile(SHADOW_FILE_NEW, []byte(newShadowFileContent), SHADOW_FILE_PERMISSIONS)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to write new shadow file to "+SHADOW_FILE_NEW, err)
	}

	_, err = ExecCmd("mv", SHADOW_FILE_NEW, SHADOW_FILE)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to override "+SHADOW_FILE+" with "+SHADOW_FILE_NEW, err)
	}

	now := time.Now()
	today := fmt.Sprintf("%d-%02d-%02d", now.Year(), now.Month(), now.Day())
	_, err = ExecCmd("chage", "-d", today, SALT_USER)
	if err != nil {
		return errorResponse("[ChangeUserPassword] Failed to update last password change date", err)
	}

	return model.Response{StatusCode: http.StatusOK}, nil
}

func errorResponse(message string, err error) (model.Response, error) {
	var detailedErr error
	if err != nil {
		detailedErr = errors.New(message + ". Error: " + err.Error())
	} else {
		detailedErr = errors.New(message)
	}
	return model.Response{ErrorText: message, StatusCode: http.StatusInternalServerError}, detailedErr
}
