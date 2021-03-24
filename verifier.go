package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type Verifier struct {
	JwksUri               string
	Issuers               []string
	Audiences             []string
	cachedCerts           *Certs
	httpClient            *http.Client
	downloadCertsTaskDone chan interface{}
	SubValidator          SubValidator
	AudienceValidator     AudienceValidator
	EmailValidator        EmailValidator
	ExpireValidator       ExpireValidator
	IssuerValidator       IssuerValidator
	CustomClaimsValidator CustomClaimsValidator
}

func NewVerifier(jwksUri string, issuers ...string) *Verifier {
	return &Verifier{
		JwksUri:               jwksUri,
		Issuers:               issuers,
		SubValidator:          subjectValidator(),
		AudienceValidator:     audienceValidator(),
		httpClient:            http.DefaultClient,
		EmailValidator:        emailValidator(),
		downloadCertsTaskDone: make(chan interface{}),
		ExpireValidator:       expireValidator(),
		IssuerValidator:       issuerValidator(issuers...),
		CustomClaimsValidator: nil,
	}
}

func (v *Verifier) AddCertsToCache(cert Certs) {
	if v.cachedCerts != nil {
		v.cachedCerts.Keys = append(v.cachedCerts.Keys, cert.Keys...)
	} else {
		v.cachedCerts = &cert
	}
}

//GetCertsFromURL is
func (v *Verifier) GetCertsFromURL(url string) ([]byte, error) {
	res, err := v.httpClient.Get(url)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download certs failed, status is %d", res.StatusCode)
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
}

func (v *Verifier) SetHttpClient(hc *http.Client) {
	if hc == nil {
		hc = http.DefaultClient
		return
	}
	v.httpClient = hc
}

func (v *Verifier) Verify(authToken string) (*TokenInfo, error) {
	//return v.VerifyWithValidator(authToken, v.SubValidator, v.AudienceValidator,
	//	v.EmailValidator, v.ExpireValidator, v.IssuerValidator, v.CustomClaimsValidator)
	return v.VerifyWithValidator(authToken)
}

func (v *Verifier) SetAudienceValidator(audienceValidator AudienceValidator) {
	v.AudienceValidator = audienceValidator
}

func (v *Verifier) SetEmailValidator(emailValidator EmailValidator) {
	v.EmailValidator = emailValidator
}
func (v *Verifier) SetExpireValidator(expireValidator ExpireValidator) {
	v.ExpireValidator = expireValidator
}
func (v *Verifier) SetIssuerValidator(issuerValidator IssuerValidator) {
	v.IssuerValidator = issuerValidator
}
func (v *Verifier) SetCustomValidator(customValidator CustomClaimsValidator) {
	v.CustomClaimsValidator = customValidator
}

func (v *Verifier) downloadCerts(url string) error {
	data, err := v.GetCertsFromURL(url)
	if err != nil {
		return err
	}

	certs, err := GetCerts(data)
	if err != nil {
		return err
	}

	v.cachedCerts = certs
	return nil
}

// Verify
func (v *Verifier) VerifyWithValidator(authToken string) (*TokenInfo, error) {
	return v.VerifyJwtToken(authToken, v.cachedCerts)
}

// VerifyJwtToken is
func (v *Verifier) VerifyJwtToken(authToken string, certs *Certs) (tokeninfo *TokenInfo, err error) {
	header, payload, signature, messageToSign := divideAuthToken(authToken)

	tokeninfo = getTokenInfo(payload)

	err = v.IssuerValidator(tokeninfo)

	if err != nil {
		return nil, err

	}
	err = v.EmailValidator(tokeninfo)
	if err != nil {
		return nil, err

	}

	err = v.SubValidator(tokeninfo)

	if err != nil {
		return nil, err

	}
	err = v.ExpireValidator(tokeninfo)

	if err != nil {
		return nil, err

	}

	err = v.AudienceValidator(tokeninfo)

	if err != nil {
		return nil, err

	}

	if certs == nil {
		fmt.Println(" Wtf")
		return nil, errors.New("CacheCerts is empty")
	}

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

func (v *Verifier) init() {
	if err := v.downloadCerts(v.JwksUri); err != nil {
		if v.cachedCerts != nil {
			panic(fmt.Errorf("download token cert failed, err is %v", err))
		}
	}

	go func() {
		ticker := time.NewTicker(time.Minute * 10)
		for {
			select {
			case <-ticker.C:
				v.downloadCerts(v.JwksUri)
			case <-v.downloadCertsTaskDone:
				return
			}
		}
	}()
}

func (v *Verifier) Close() {
	close(v.downloadCertsTaskDone)
}
