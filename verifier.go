package main

import (
	"log"
)

type Verifier struct {
	JwksUri              string
	Issuers              []string
	Audiences             []string
	SubValidator         Validator
	AudienceValidator    Validator
	EmailValidator       Validator
	ExpireValidator      Validator
	IssuerValidator      Validator
	CustomCalmsValidator Validator
}

func NewVerifier(jwksUri string, issuers ... string ) *Verifier  {
	return &Verifier{
		JwksUri:              jwksUri,
		Issuers:              issuers,
		SubValidator:         nil,
		AudienceValidator:    &AudienceValidator,
		EmailValidator:       nil,
		ExpireValidator:      nil,
		IssuerValidator:      IssuerValidator(),
		CustomCalmsValidator: nil,
	}
}

func (v *Verifier) Verify(authToken string) (*TokenInfo, error) {
	return Verify(authToken, v.SubValidator, v.AudienceValidator,
		v.EmailValidator, v.ExpireValidator, v.IssuerValidator, v.CustomCalmsValidator)
}

func IssuerValidator() Validator {
	return func(tokeninfo *TokenInfo) error {
		issValid := false
		for _, iss := range Issuers {
			issValid = issValid || (tokeninfo.Iss == iss)
		}
		if !issValid {
			return ErrInvalidIssuer
		}
		return nil
	}
}

//func AudienceValidator(audience string) Validator {
//
//	return func(tokeninfo *TokenInfo) error {
//		log.Println(audience != tokeninfo.Aud)
//		if audience != tokeninfo.Aud {
//			return ErrInvalidAudience
//		}
//		return nil
//	}
//}

func AudienceValidator() Validator {

	return func(tokeninfo *TokenInfo) error {

		if audience != tokeninfo.Aud {
			return ErrInvalidAudience
		}
		return nil
	}
}

func EmailValidator(email string) Validator {
	return func(tokeninfo *TokenInfo) error {
		if email != tokeninfo.Email {
			return ErrInvalidEmail
		}
		return nil
	}
}

func ExpireValidator() Validator {
	return func(tokeninfo *TokenInfo) error {
		if !checkTime(tokeninfo) {
			return ErrTokenExpired
		}
		return nil
	}
}
