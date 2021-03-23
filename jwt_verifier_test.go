package google

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheckDexToken(t *testing.T) {
	tv := TokenVerifier{
		JwksUri: "http://127.0.0.1:5556/dex/keys",
		Issuer:  []string{"http://127.0.0.1:5556/dex"},
	}

	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlMGNjZjk5YjkyNzg1YzZkMDgxYTVhMzFlZjZhMzExZjE2NTExNjgifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2lOamJqMXFZVzVsTEc5MVBWQmxiM0JzWlN4a1l6MWxlR0Z0Y0d4bExHUmpQVzl5WnhJRWJHUmhjQSIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNjE2NTU1Mjc2LCJpYXQiOjE2MTY0Njg4NzYsImF6cCI6ImV4YW1wbGUtYXBwIiwiYXRfaGFzaCI6IlQ2am1ta3BZZFNqV3ZCb1EyR0xORWciLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImphbmUifQ.sFDeZnTWsHvRo6m8qqOS-bDtO1ZZ0cADogcAJTZX90sdP5HY6XdkGnm4FBD6BqKiKsTaIudTgJq9mJSFFcACRHv_Lpb0OSu4rS3HtbgiQhXJvQDNTWcXx3sqLC-SWfVwBCEzGA3WVNw1odA3lBQXvGcanCC1QPTqq9opqOIhmBPUx_p4vWB1R08owFPRyBSQBKeGT66SRva89uqe-CP1dzFHNBHvDkgMuS607QraOWQ43wczR7xg5Apm1GYW9f5drR1rZaLDOnt2xl58pDLMnpIbgCmqr9_pGiNmIujx_03A-32oK4PHzvLlwy0GwAXMUjcehuv-GDUpnh7-B_rj4A"
	aud := "example-app"
	actual := tv.Verify(authToken, aud)
	//var token *TokenInfo
	//expected := token
	//if actual != expected {
	//	t.Errorf("got %v\nwant %v", actual, expected)
	//}
	assert.Equal(t, actual.Iss, "http://127.0.0.1:5556/dex")
}

func TestCheckDexToken_ErrWhenGetCerts(t *testing.T) {
	tv := TokenVerifier{
		JwksUri: "http://127.0.0.1:5556/dex/keys111",
		Issuer:  []string{"http://127.0.0.1:5556/dex"},
	}
	var token *TokenInfo
	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlMGNjZjk5YjkyNzg1YzZkMDgxYTVhMzFlZjZhMzExZjE2NTExNjgifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2lOamJqMXFZVzVsTEc5MVBWQmxiM0JzWlN4a1l6MWxlR0Z0Y0d4bExHUmpQVzl5WnhJRWJHUmhjQSIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNjE2NTU1Mjc2LCJpYXQiOjE2MTY0Njg4NzYsImF6cCI6ImV4YW1wbGUtYXBwIiwiYXRfaGFzaCI6IlQ2am1ta3BZZFNqV3ZCb1EyR0xORWciLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImphbmUifQ.sFDeZnTWsHvRo6m8qqOS-bDtO1ZZ0cADogcAJTZX90sdP5HY6XdkGnm4FBD6BqKiKsTaIudTgJq9mJSFFcACRHv_Lpb0OSu4rS3HtbgiQhXJvQDNTWcXx3sqLC-SWfVwBCEzGA3WVNw1odA3lBQXvGcanCC1QPTqq9opqOIhmBPUx_p4vWB1R08owFPRyBSQBKeGT66SRva89uqe-CP1dzFHNBHvDkgMuS607QraOWQ43wczR7xg5Apm1GYW9f5drR1rZaLDOnt2xl58pDLMnpIbgCmqr9_pGiNmIujx_03A-32oK4PHzvLlwy0GwAXMUjcehuv-GDUpnh7-B_rj4A"
	aud := "example-app"
	actual := tv.Verify(authToken, aud)
	assert.Equal(t, actual, token)
}

func TestCheckDexToken_InvalidIssuer(t *testing.T) {
	tv := TokenVerifier{
		JwksUri: "http://127.0.0.1:5556/dex/keys",
		Issuer:  []string{"http://127.0.0.1:5556/dex1"},
	}
	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVlMGNjZjk5YjkyNzg1YzZkMDgxYTVhMzFlZjZhMzExZjE2NTExNjgifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2lOamJqMXFZVzVsTEc5MVBWQmxiM0JzWlN4a1l6MWxlR0Z0Y0d4bExHUmpQVzl5WnhJRWJHUmhjQSIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNjE2NTU1Mjc2LCJpYXQiOjE2MTY0Njg4NzYsImF6cCI6ImV4YW1wbGUtYXBwIiwiYXRfaGFzaCI6IlQ2am1ta3BZZFNqV3ZCb1EyR0xORWciLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImphbmUifQ.sFDeZnTWsHvRo6m8qqOS-bDtO1ZZ0cADogcAJTZX90sdP5HY6XdkGnm4FBD6BqKiKsTaIudTgJq9mJSFFcACRHv_Lpb0OSu4rS3HtbgiQhXJvQDNTWcXx3sqLC-SWfVwBCEzGA3WVNw1odA3lBQXvGcanCC1QPTqq9opqOIhmBPUx_p4vWB1R08owFPRyBSQBKeGT66SRva89uqe-CP1dzFHNBHvDkgMuS607QraOWQ43wczR7xg5Apm1GYW9f5drR1rZaLDOnt2xl58pDLMnpIbgCmqr9_pGiNmIujx_03A-32oK4PHzvLlwy0GwAXMUjcehuv-GDUpnh7-B_rj4A"
	aud := "example-app"
	actual := tv.Verify(authToken, aud)
	var token *TokenInfo
	assert.Equal(t, actual, token)
}

func TestCheckGoogleToken_InvalidIssuer(t *testing.T) {
	tv := TokenVerifier{
		JwksUri: "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:  []string{"https://accounts.google.com"},
	}
	authToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0NjJhNzFkYTRmNmQ2MTFmYzBmZWNmMGZjNGJhOWMzN2Q2NWU2Y2QiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzNjMxMDc5ODc4ODYtOXZmbWtsOWpvaGhyN2tobnQwamZhNjhwanJrMGtqZjcuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzNjMxMDc5ODc4ODYtOXZmbWtsOWpvaGhyN2tobnQwamZhNjhwanJrMGtqZjcuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIwMTA2OTA3MjIyMjU2NTMyMDgiLCJlbWFpbCI6ImJsYWNrcHJlc2lkZW50OTBAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJWendiV2xScWtWbzhaYjBPQURtaXJRIiwiaWF0IjoxNjE1NTMzMDYxLCJleHAiOjE2MTU1MzY2NjF9.VY4EBQsfOm0fwSpkrUU5mY4MPz9DTik8U0JDLDWf8sVTji1v1lp4Cs0krAkUVZaEe3Wip0aMTcnz2AvdtCydNzZKqw_nxq5LYBKDZbBRd7iuL6I2EdBbFWLEJrTGnCpMtw99OqVrTT4DNLsN5cVbQv_dzhZztk2-VpFI6hR9UaerE4J0xwEZV30GF-4keXROpsxUr1zYVxLJCjSifHnMFtve3LrQAC_AYI0x6fKrJhcT7wVXFHJp22XHXrCYDRtuHDSOqmhIoUKmaOyepaSc4xVPNZfKq8OUgQDYdQG8AW76r7M83NwPlnECai0vGvND4t9N81gVjzxrai-qCRcg_g"
	aud := "363107987886-9vfmkl9johhr7khnt0jfa68pjrk0kjf7.apps.googleusercontent.com"
	actual := tv.Verify(authToken, aud)
	var token *TokenInfo
	assert.Equal(t, actual, token)
}