package saltboot

import (
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"github.com/kless/osutil/user/crypt/sha512_crypt"
)

const SALT_USER = "saltuser"

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

func CreateUser(saltMaster SaltMaster) (resp model.Response, err error) {
	log.Printf("[CreateUser] execute salt run request")

	result := "OK"

	//saltUser, _ := user.Lookup(SALT_USER) //requires cgo
	out, err := ExecCmd("grep", SALT_USER, "/etc/passwd")

	if len(out) == 0 || err != nil {
		log.Printf("[CreateUser] user: %s does not exsist and will be created", SALT_USER)

		c := sha512_crypt.New()

		// Password needs to be "salted" and must start with a magic prefix
		salt := "$6$" + randStringRunes(20)

		hash, err := c.Generate([]byte(saltMaster.Auth.Password), []byte(salt))
		if err != nil {
			return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
		}
		result, err = ExecCmd("adduser", "--no-create-home", "-G", "wheel", "-s", "/sbin/nologin", "--password", hash, SALT_USER)

		if err != nil {
			return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
		}
	} else {
		log.Printf("[CreateUser] user: %s exsist", SALT_USER)
	}

	resp = model.Response{Status: result, StatusCode: http.StatusOK}
	return resp, nil

}
