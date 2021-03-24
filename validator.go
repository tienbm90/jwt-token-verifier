package main

type (
	Validator func(*TokenInfo) error
	SubValidator func(*TokenInfo) error
	AudienceValidator func(*TokenInfo) error
	EmailValidator func(*TokenInfo) error
	ExpireValidator func(*TokenInfo) error
	IssuerValidator func(*TokenInfo) error
	CustomClaimsValidator func(*TokenInfo) error
)

func issuerValidator(issuers ...string) IssuerValidator {
	return func(tokeninfo *TokenInfo) error {
		issValid := false
		for _, iss := range issuers {
			issValid = issValid || (tokeninfo.Iss == iss)
		}
		if !issValid {
			return ErrInvalidIssuer
		}
		return nil
	}
}

func subjectValidator(subs ...interface{}) SubValidator {
	return func(tokenInfo *TokenInfo) error {
 		if tokenInfo.Sub == "" {
			return ErrInvalidSubject
		}
		return nil
	}
}

func audienceValidator(audiences ...interface{}) AudienceValidator {
	return func(tokenInfo *TokenInfo) error {
		if tokenInfo.Aud == "" {
			return ErrInvalidAudience
		}
		if len(audiences) > 0 {
			for _, aud := range audiences {
				if aud == tokenInfo.Aud {
					return nil
				}
			}
			return ErrInvalidAudience
		}
		return nil
	}
}

func emailValidator(emails ...interface{}) EmailValidator {
	return func(tokeninfo *TokenInfo) error {
		if tokeninfo.Email == "" {
			return ErrInvalidEmail
		}
		return nil
	}
}

func expireValidator(expires ...interface{}) ExpireValidator {
	return func(tokeninfo *TokenInfo) error {
		if !checkTime(tokeninfo) {
			return ErrTokenExpired
		}
		return nil
	}
}
