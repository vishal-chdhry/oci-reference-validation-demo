package oci

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
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

	policyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "trust-policy",
				RegistryScopes:        []string{"localhost:5000/lachie/net-monitor"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	signatureEnvelope := generateSignatureEnvelope(exampleCertTuple.PrivateKey)

	verifyOptions := notation.VerifyOptions{
		ArtifactReference:  artifactReference,
		SignatureMediaType: exampleSignatureMediaType,
	}

	if err := createTrustStore(exampleCertTuple.Cert); err != nil {
		panic(err)
	}

	notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err)
	}

	outcome, err := notationVerifier.Verify(ctx, targetDesc, signatureEnvelope, verifyOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully verified")

	fmt.Println("payload ContentType:", outcome.EnvelopeContent.Payload.ContentType)
	fmt.Println("payload Content:", string(outcome.EnvelopeContent.Payload.Content))

	return err
}

func Fluxcd_demo() error {
	return nil
}

func generateSignatureEnvelope(key *rsa.PrivateKey) []byte {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "SIGNATURE ENVELOPE",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	println(string(pemdata))
	return pemdata
}

func createTrustStore(cert *x509.Certificate) error {
	dir.UserConfigDir = "tmp"

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	println(string(pubBytes))

	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/Notation.pem", pubBytes, 0600)
}
