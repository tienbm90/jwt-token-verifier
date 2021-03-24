package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_AudienceValidator(t *testing.T) {

	verifier := NewVerifier("http://127.0.0.1:5556/dex/keys", "http://127.0.0.1:5556/dex", "http://127.0.0.1:5557/dex")
	verifier.init()
	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3M2M2MmQ5ZDhlYWI4NzEzODE1Y2QzNmFlZDdhZTFkNTM3NjY4MGMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2lOamJqMXFZVzVsTEc5MVBWQmxiM0JzWlN4a1l6MWxlR0Z0Y0d4bExHUmpQVzl5WnhJRWJHUmhjQSIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNjE2NjQ0OTMzLCJpYXQiOjE2MTY1NTg1MzMsImF0X2hhc2giOiJJSG1rTjZ2MFBNUnc4Snk1Z05GYkxnIiwiZW1haWwiOiJqYW5lZG9lQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJqYW5lIn0.Y7SB8po-e88C_3nz9huzYFYuqzJ7wWFqN88F8Seh1VPTCEj-TktifG9guPGm2EaG5uCyDUWM3LyOwEE7yIoMcwFMm_vTQONuAaNeiCKIdxB-k-C771cBaxdZgaO_vgd5JgWPCFiGKWyOu80FRIen0_uDjPFidj5JyupTTOk9_2384MXFnoTln4vB1tMoZy1sMrX9gaSyGrPAKEsNrTmR3Hyi0ldFwy4GT4L30rRgpiP_eGdCN0PtJuTlTK9y2RaGcdttX2aZak_IkLuknS1PrzNb4BqtDRmDOFCxbkKIyuGYHmg5cDCniGl-R3Yj42aFgjsA_E8tZIcwl3p_BS3N-g"
	aud := "example-app"

	actual, err := verifier.Verify(authToken)
	assert.Equal(t, nil, err)
	assert.Equal(t, aud, actual.Aud)

	defer verifier.Close()
	//assert.Equal(t, actual.Iss, "http://127.0.0.1:5556/dex")
}

func Test_With_CustomCerts(t *testing.T) {
	verifier := NewVerifier("http://127.0.0.1:5556/dex/keys1", "http://127.0.0.1:5556/dex", "http://127.0.0.1:5557/dex")
	//verifier.init()

	certStr := `
{
"keys": [
{
"use": "sig",
"kty": "RSA",
"kid": "773c62d9d8eab8713815cd36aed7ae1d5376680c",
"alg": "RS256",
"n": "2G6CjW5JooPevM2UDd_dE9EMzQEJXeJyau6F7sM_7j9wdiOMJubCrYX0DZ4mpgQlfdL1OeNOUqcLDaAutZ16SFCIMSpArluqb5O63h8s50KORO7Gpoh7PIuepF2RlO2T47VRfy8NxN2L_EXFf8UuLuGd65xVbfarxtSnvvmP7LtwxC8E-MqC3OmdEYCpjjDUCtAJi1EUpI77VTOGGmdoThxAOOIDWYf00N7qqQ1SIBjauDFHN89KiYN5OE6Fbcgkdj6TtZG2UfPbXBgl5woo1cwpKc764zYzWIO-DKjR_4JFWgKdikFgVCqt1hS2vUCOunN2l1fVY8DqND1daXkn1w",
"e": "AQAB"
}
]
}`
	var cert Certs

	json.Unmarshal([]byte(certStr), &cert)

	for _, key := range cert.Keys {
		key.init()
	}

	verifier.AddCertsToCache(cert)
	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3M2M2MmQ5ZDhlYWI4NzEzODE1Y2QzNmFlZDdhZTFkNTM3NjY4MGMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2lOamJqMXFZVzVsTEc5MVBWQmxiM0JzWlN4a1l6MWxlR0Z0Y0d4bExHUmpQVzl5WnhJRWJHUmhjQSIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNjE2NjQ0OTMzLCJpYXQiOjE2MTY1NTg1MzMsImF0X2hhc2giOiJJSG1rTjZ2MFBNUnc4Snk1Z05GYkxnIiwiZW1haWwiOiJqYW5lZG9lQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJqYW5lIn0.Y7SB8po-e88C_3nz9huzYFYuqzJ7wWFqN88F8Seh1VPTCEj-TktifG9guPGm2EaG5uCyDUWM3LyOwEE7yIoMcwFMm_vTQONuAaNeiCKIdxB-k-C771cBaxdZgaO_vgd5JgWPCFiGKWyOu80FRIen0_uDjPFidj5JyupTTOk9_2384MXFnoTln4vB1tMoZy1sMrX9gaSyGrPAKEsNrTmR3Hyi0ldFwy4GT4L30rRgpiP_eGdCN0PtJuTlTK9y2RaGcdttX2aZak_IkLuknS1PrzNb4BqtDRmDOFCxbkKIyuGYHmg5cDCniGl-R3Yj42aFgjsA_E8tZIcwl3p_BS3N-g"
	aud := "example-app"
	actual, err := verifier.VerifyWithValidator(authToken)
	assert.Nil(t, err)
	assert.Equal(t, aud, actual.Aud)
	defer verifier.Close()

}
