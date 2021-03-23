package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	httpClient            *http.Client = http.DefaultClient
	JwksUri               string       = "https://www.googleapis.com/oauth2/v3/certs"
	Issuers               []string     = []string{"accounts.google.com", "https://accounts.google.com"}
	downloadCertsTaskDone chan interface{}
	cachedCerts           *Certs
	ErrInvalidIssuer   = errors.New("Token is not valid, ISS from token and certificate don't match")
	ErrInvalidAudience = errors.New("Token is not valid, Audience from token and certificate don't match")
	ErrInvalidEmail    = errors.New("Token is not valid, Email from token and certificate don't match")
	ErrTokenExpired    = errors.New("Token is not valid, Token is expired.")
	ErrInvalidKid      = errors.New("Token is not valid, kid from token and certificate don't match")
)

type Validator func(*TokenInfo) error

// Certs is
type Certs struct {
	Keys []*keys `json:"keys"`
}

type keys struct {
	Kty       string         `json:"kty"`
	Alg       string         `json:"alg"`
	Use       string         `json:"use"`
	Kid       string         `json:"Kid"`
	N         string         `json:"n"`
	E         string         `json:"e"`
	PublicKey *rsa.PublicKey `json:"-"`
	Hash      crypto.Hash    `json:"-"`
}

// TokenInfo is
type TokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Local         string `json:"locale"`
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// https://developers.google.com/identity/sign-in/web/backend-auth
// https://github.com/google/oauth2client/blob/master/oauth2client/crypt.py

func init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}

	jwksUri := os.Getenv("IDP_JWKSURI")
	rawIssuers := os.Getenv("IDP_ISSUSERS")

	issusers := strings.Split(rawIssuers, ",")

	SetJwksUri(jwksUri)
	SetIssuers(issusers)
	if err := downloadCerts(); err != nil {
		panic(fmt.Errorf("download token cert failed, err is %v", err))
	}

	go func() {
		ticker := time.NewTicker(time.Minute * 10)
		for {
			select {
			case <-ticker.C:
				downloadCerts()
			case <-downloadCertsTaskDone:
				return
			}
		}
	}()
}

func downloadCerts() error {
	data, err := GetCertsFromURL()
	if err != nil {
		return err
	}

	certs, err := GetCerts(data)
	if err != nil {
		return err
	}

	cachedCerts = certs
	return nil
}

func SetHttpClient(hc *http.Client) {
	if hc == nil {
		hc = http.DefaultClient
		return
	}
	httpClient = hc
}

func SetJwksUri(uri string) {
	if uri == "" {
		JwksUri = "https://www.googleapis.com/oauth2/v3/certs"
		return
	}
	JwksUri = uri
}

func SetIssuers(issuers []string) {
	if len(issuers) <= 0 {
		Issuers = []string{"accounts.google.com", "https://accounts.google.com"}
		return
	}
	Issuers = issuers
}

func Close() {
	close(downloadCertsTaskDone)
}


// Verify
func Verify(authToken string, validators ...Validator) (*TokenInfo, error) {
	return VerifyJwtToken(authToken, cachedCerts, validators...)
}

// VerifyJwtToken is
func VerifyJwtToken(authToken string, certs *Certs, validators ...Validator) (tokeninfo *TokenInfo, err error) {
	header, payload, signature, messageToSign := divideAuthToken(authToken)

	tokeninfo = getTokenInfo(payload)
	for _, validator := range validators {
		if err = validator(tokeninfo); err != nil {
			return
		}
	}
	fmt.Println(getAuthTokenKeyID(header))
	fmt.Println(certs.Keys)

	for _, key := range certs.Keys {
		fmt.Println(key)
	}
	var key *keys
	key, err = choiceKeyByKeyID(certs.Keys, getAuthTokenKeyID(header))
	if err != nil {
		return
	}
	err = rsa.VerifyPKCS1v15(key.PublicKey, key.Hash, messageToSign, signature)
	return
}

func getTokenInfo(bt []byte) *TokenInfo {
	var a *TokenInfo
	json.Unmarshal(bt, &a)
	return a
}

func checkTime(tokeninfo *TokenInfo) bool {
	if (time.Now().Unix() < tokeninfo.Iat) || (time.Now().Unix() > tokeninfo.Exp) {
		return false
	}
	return true
}

//GetCertsFromURL is
func GetCertsFromURL() ([]byte, error) {
	res, err := httpClient.Get(JwksUri)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download certs failed, status is %d", res.StatusCode)
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
}

//GetCerts is
func GetCerts(bt []byte) (*Certs, error) {
	var certs *Certs
	err := json.Unmarshal(bt, &certs)
	if err != nil {
		return nil, err
	}

	for _, key := range certs.Keys {
		key.init()
	}

	return certs, nil
}

func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}

func choiceKeyByKeyID(a []*keys, tknkid string) (*keys, error) {
	for _, key := range a {
		if key.Kid == tknkid {
			return key, nil
		}
	}
	//var b keys
	//return b, err
	return nil, ErrInvalidKid
}

func getAuthTokenKeyID(bt []byte) string {
	var a keys
	json.Unmarshal(bt, &a)
	return a.Kid
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte) {
	args := strings.Split(str, ".")
	return urlsafeB64decode(args[0]), urlsafeB64decode(args[1]), urlsafeB64decode(args[2]), calcSum(args[0] + "." + args[1])
}

func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}

func calcSum(str string) []byte {
	a := sha256.New()
	a.Write([]byte(str))
	return a.Sum(nil)
}

func btrToInt(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}

func (key *keys) init() {
	key.PublicKey = &rsa.PublicKey{
		N: byteToInt(urlsafeB64decode(key.N)),
		E: btrToInt(byteToBtr(urlsafeB64decode(key.E))),
	}
	key.Hash = crypto.SHA256
}
