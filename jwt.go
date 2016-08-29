package jwt

import (
	"errors"
	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"net/http"
	"time"
)

type JwtConf struct {
	privateKeyFile         string
	publicKeyFile          string
	privateKey             []byte
	publicKey              []byte
	algorithm              string
	sessionName            string
	sessionTimeout         int
	sessionRefreshInterval int
}

type Jwt struct {
	initialized bool
	conf *JwtConf
}

var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

var std = &Jwt{
	initialized: true,
	conf: &JwtConf{
		privateKeyFile: "",
		publicKeyFile: "",
		privateKey: []byte("secret"),
		publicKey: []byte("secret"),
		algorithm: "RS256",
		sessionName  : "secret",
		sessionTimeout:  3000,
		sessionRefreshInterval: 300,
	},
}

func (j *Jwt) Configure (cnf map[string]interface{}) error {
	ok := false
	var err error
	if j.conf.privateKeyFile, ok = cnf["privateKeyFile"].(string); !ok{
		return errors.New("Private key file not specified")
	}
	if j.conf.publicKeyFile, ok = cnf["publicKeyFile"].(string); !ok {
		return errors.New("Public key file not specified")
	}
	if j.conf.algorithm, ok = cnf["algorithm"].(string); !ok {
		return errors.New("Public key file not specified")
	}
	if j.conf.sessionName, ok = cnf["sessionName"].(string); !ok {
		return errors.New("Session name not specified")
	}
	if j.conf.sessionTimeout, ok = cnf["sessionTimeout"].(int); !ok {
		return errors.New("session timeout not specified")
	}
	if j.conf.sessionRefreshInterval, ok = cnf["sessionRefreshInterval"].(int); !ok {
		return errors.New("session refresh interval not specified")
	}
	if j.conf.privateKey, err = ioutil.ReadFile(j.conf.privateKeyFile); err != nil {
		return err
	}
	if j.conf.publicKey, err = ioutil.ReadFile(j.conf.publicKeyFile); err != nil {
		return err
	}
	std.initialized = true
	return nil
}

func Configure(cnf map[string]interface{}) error {
	if err := std.Configure(cnf); err != nil{
		return err
	}
	return nil
}

func CreateToken(user map[string]interface{}, w http.ResponseWriter, r *http.Request) (string, error) {

	t := gojwt.New(gojwt.GetSigningMethod(std.conf.algorithm))
	user["exp"] = float64(time.Now().Add(time.Second * time.Duration(std.conf.sessionTimeout)).Unix())
	
	t.Claims["user"] = user
	tokenString, err := t.SignedString(std.conf.privateKey)
	session, _ := store.Get(r, std.conf.sessionName)
	session.Values["token"] = tokenString
	session.Save(r, w)
	return tokenString, err
}

func ParseToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	session, err := store.Get(r, std.conf.sessionName)
	if err != nil {
		return nil, err
	}
	var tokenString string
	switch session.Values["token"].(type) {
	case string:
		tokenString = session.Values["token"].(string)
	default:
		return nil, errors.New("Invalid cookie")
	}
	var user = make(map[string]interface{})
	token, err := gojwt.Parse(tokenString, func(token *gojwt.Token) (interface{}, error) {
		return std.conf.publicKey, nil
	})

	if err == nil && token.Valid {
		user = token.Claims["user"].(map[string]interface{})
		//user["exp"] = user["exp"].(int64)
		er := RefreshToken(user, w, r)
		if er != nil {
			return user, er
		}
		return user, err
	} else {
		//Invalid token
		return user, err
	}
}

func RefreshToken(user map[string]interface{}, w http.ResponseWriter, r *http.Request) error {
	exp := user["exp"].(float64)
	now := time.Now().Unix()
	remain := exp - float64(now)
	timeout := float64(std.conf.sessionTimeout)
	interval := float64(std.conf.sessionRefreshInterval)
	timeToRefresh := remain < (timeout - interval)
	if !timeToRefresh {
		return nil
	}

	if remain <= 0 {
		return errors.New("Session timed out")
	}

	t := gojwt.New(gojwt.GetSigningMethod(std.conf.algorithm))
	user["exp"] = time.Now().Add(time.Second * time.Duration(std.conf.sessionTimeout)).Unix()

	t.Claims["user"] = user

	tokenString, err := t.SignedString(std.conf.privateKey)

	session, err := store.Get(r, std.conf.sessionName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return err
	}

	session.Values["token"] = tokenString
	session.Save(r, w)
	return err
}
