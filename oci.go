package oci

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func ORAS_demo() error {
	ctx := context.Background()

	fmt.Println("Setting up local repository")
	reg := "localhost:5000"
	repo, err := remote.NewRepository(reg + "/lachie/net-monitor:v1")
	if err != nil {
		panic(err)
	}

	repo.PlainHTTP = true
	fmt.Println("Repo: ", repo.Reference.Repository)
	fmt.Println("Reference: ", repo.Reference.Reference)

	fmt.Println("Fetching the repository from registry")
	repoDescriptor, readCloser, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Digest: ", repoDescriptor.Digest.String())
	buf := new(bytes.Buffer)
	buf.ReadFrom(readCloser)
	fmt.Println("Manifest: ", buf.String())
	readCloser.Close()
	artifactReference := reg + "/" + repo.Reference.Repository + "@" + repoDescriptor.Digest.String()

	// Remote signing using notation
	fmt.Println("Remote signing using notation")
	exampleCertTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	exampleCerts := []*x509.Certificate{exampleCertTuple.Cert}
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err)
	}
	println(exampleCertTuple.PrivateKey)
	exampleSignatureMediaType := cose.MediaTypeEnvelope

	exampleSignOptions := notation.RemoteSignOptions{
		SignOptions: notation.SignOptions{
			ArtifactReference:  artifactReference,
			SignatureMediaType: exampleSignatureMediaType,
		},
	}

	exampleRepo := registry.NewRepository(repo)

	targetDesc, err := notation.Sign(context.Background(), exampleSigner, exampleRepo, exampleSignOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully signed")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	fmt.Println("Fetching the referrers of a manifest from registry")
	referrersLink := "http://" + reg + "/v2/" + repo.Reference.Repository + "/referrers/" + repoDescriptor.Digest.String()
	resp, err := http.Get(referrersLink)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	ref := string(body)
	fmt.Println("Referrers:", ref)

	fmt.Println("Verifing that the image is signed properly using Local Verification")
	fmt.Println("Artifact Reference:", artifactReference)

	// policyDocument := trustpolicy.Document{
	// 	Version: "1.0",
	// 	TrustPolicies: []trustpolicy.TrustPolicy{
	// 		{
	// 			Name:                  "trust-policy",
	// 			RegistryScopes:        []string{"*"},
	// 			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
	// 			TrustStores:           []string{"ca:valid-trust-store"},
	// 			TrustedIdentities:     []string{"*"},
	// 		},
	// 	},
	// }

	// signatureEnvelope := generateSignatureEnvelope()

	// verifyOptions := notation.VerifyOptions{
	// 	ArtifactReference:  artifactReference,
	// 	SignatureMediaType: exampleSignatureMediaType,
	// }

	// if err := createTrustStore(string(signerInfo.CertificateChain[0].SerialNumber.Bytes())); err != nil {
	// 	panic(err)
	// }

	// notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	// if err != nil {
	// 	panic(err)
	// }

	// outcome, err := notationVerifier.Verify(ctx, repoDescriptor, signatureEnvelope, verifyOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Successfully verified")

	// fmt.Println("payload ContentType:", outcome.EnvelopeContent.Payload.ContentType)
	// fmt.Println("payload Content:", string(outcome.EnvelopeContent.Payload.Content))

	return err
}

func Fluxcd_demo() error {
	return nil
}

func generateSignatureEnvelope() []byte {
	signatureEnvelopePem := `-----BEGIN EXAMPLE SIGNATURE ENVELOPE-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDN7Z01UxG2D+h2
HQT3hqR0nlQPs9WW/dcpT5GaSsqupxbikcgKOhP1egohx3+iXDMmleTZ8RVO6pWe
leWGbp2LpXo/zJ9xl6KWbWnBYYUv5Y0JEDmWioEUNwt8uB/9Az8wLgatODKvTR1E
5MRCX6yNgD4AO+Q9dG2mBYU82FSsWGOVhcM9BFsctMyf0VCX3xBZeU+ofrWFf0f1
ID74C6oQimjOQ+q95aEYqW4VZadGiWWrMv9pdDxLuLRHu1aNp85y/troONynv44p
Hl9wR+KShy2GUSU/izNqIZr72z1Op7VHZU2TZp0APxSvuANQrjn5FCxrp0CZFblT
u2T97Hl5AgMBAAECggEAF42+FYNS20gmhpv7HXTBCrWxV7pyC7stCQSY2tUDKcbi
zzdtcf4CmmlDD2oKJz/0ec1bR7JThZs/UcxDXIT6cCaVPQbildOKPTp2hi/pU/kl
kIvSim19JhrFrZZB0ma0q4YYLWfoJDTlzCN+bzkSO30Xml8/U+glQoAPJU55IN0m
dpXEudLExmcTCBoLgLjazaXaqvxFpLdxOJvkiC8qLuLcog5L9EhlXhlQG2X6Di52
5z7Ke4MkNVbLhKQpqP71wU2chaQP/olYMONDLT341gDDJpwOVl2TFj80beg0sD47
n2GtZX2Px8ebeXefQflXY96mr6lwbRgRsyBogW28oQKBgQD/AIPnfdrX9Ih8/4bS
MHLU9yP9Bp0l+E1sEiJJ0SWX0DA4zdaVR/ggGrtPPzbtB6aIf3B6aC6l6YRwG9Cc
zuhdl5ox8uK1lzH6ICwsZAFINzX6giyhC21ueLWwO4xrngL6HYa3+PUD9q8AUsPu
TKGVRrTKLN2Scs6tXovH63GVjwKBgQDOu+6e1ZU0tHkI5Guz2++G14TZ2ANq6EYl
pvvem/sHHcFXcxOD0ZQbaIcuP7U8JxlVMHuy03QLB2UkXI9B5uOMK1RXbhORzUwM
/eZP/cGdOe5ByoWcb9DycGMVMqAl0vftyhBrSKb3qN3VfNBEOh/+rct9E+Oh57Hp
+GR+Iu7MdwKBgQCGKg48ULJApw7cvVCA7C6ur+0GZmFuJcsOTiguMFUYH9gPOvVo
i3oX4hik5DyQz1KmRG64aHIKpucgWPIUXqRRAb+GAiWXpxoLYLv9CwzFow7KY4z5
mlqUIfxt4ZbK1FL6p2hHCTxYPoTqpaEikrz9Hjtml95n+/GTs8fVgqG7LwKBgFb3
JbU5Yc/PD49XD5uUrJlLtj4xqZZiaYfTS+bkNOBUew2/gfkUw7oX6a3h7OqGBBkb
ER4z53/wN3LpYPY3G4fOfmddDexqsVBRyn3h4H20be7NNBGP1BT4hCXZqxbePZ+R
PgDzihFqvw7ct3vL+8OV9qECKeLk5ann7NZG+a+XAoGAedSYpq8q4cEOHVmXfstn
c5Y96cKOr0S+LvMOte7o1/H31yF40t1qDUEhm00fNI+naOYbyVSRn158FRqymAlR
sHOrITL3adgfp2nb7Z2vY1SkvWHbSn3XZWCTX9WcRW3FV32YTjGQ5kdwwvTV7rtV
Set1orWJONX1jRP14OAYCQE=
-----END EXAMPLE SIGNATURE ENVELOPE-----`

	block, _ := pem.Decode([]byte(signatureEnvelopePem))
	if block == nil {
		panic(errors.New("invalid signature envelope pem block"))
	}

	return block.Bytes
}

func createTrustStore(cert string) error {
	dir.UserConfigDir = "tmp"
	exampleX509Certificate := `-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIBUjANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEb
MBkGA1UEAxMSd2FiYml0LW5ldHdvcmtzLmlvMB4XDTIzMDMxMzE4NDkyMVoXDTIz
MDMxNDE4NDkyMVowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQH
EwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxGzAZBgNVBAMTEndhYmJpdC1uZXR3
b3Jrcy5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM3tnTVTEbYP
6HYdBPeGpHSeVA+z1Zb91ylPkZpKyq6nFuKRyAo6E/V6CiHHf6JcMyaV5NnxFU7q
lZ6V5YZunYulej/Mn3GXopZtacFhhS/ljQkQOZaKgRQ3C3y4H/0DPzAuBq04Mq9N
HUTkxEJfrI2APgA75D10baYFhTzYVKxYY5WFwz0EWxy0zJ/RUJffEFl5T6h+tYV/
R/UgPvgLqhCKaM5D6r3loRipbhVlp0aJZasy/2l0PEu4tEe7Vo2nznL+2ug43Ke/
jikeX3BH4pKHLYZRJT+LM2ohmvvbPU6ntUdlTZNmnQA/FK+4A1CuOfkULGunQJkV
uVO7ZP3seXkCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQAJnuwWHN6mVhr+E7cJAZmfmbYx0i3R
O8iRdfvoJjKhc+3Il2PJ3v4dxsF5HO/chQDVRoEMRax0p3e/w5hAEf4UlOsrQ3qY
DHBEwi6Vmiwt43LHZfpQz4DfLYBZ+33JjdPvVW65j/z0cODox3QTMeR3w2JqWudY
bxDyNE0aN+ppXflkreRIPslnF1fFzWxYUYDO4qkrTWpCmJZGRIX5GAaGMSroq7cr
/OitWnJfNkTlFg0q9xGZ5RzJv7PYqFbPJ3Fj3Uon77uw/4ypsNYMEEOfkld9s6Xh
iMxdWnnXVhq8jFmP/mLCT+cVGpB1NXdeEftIuJN+xjWmnRZi/vmGlYlQ
-----END CERTIFICATE-----`

	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationLocalExample.pem", []byte(exampleX509Certificate), 0600)
}
