package oci

import (
	"bytes"
	"context"
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
	fmt.Println("\n-----Setting up local repository-----")
	fmt.Println()
	reg := "localhost:5000"
	repo, err := remote.NewRepository(reg + "/lachie/net-monitor:v1")
	if err != nil {
		panic(err)
	}

	repo.PlainHTTP = true
	fmt.Println("Registry: ", repo.Reference.Registry)
	fmt.Println("Repository: ", repo.Reference.Repository)
	fmt.Println("Reference: ", repo.Reference.Reference)

	//
	// Fetching the repository from registry
	//
	fmt.Println("\n-----Fetching the repository from registry-----")
	fmt.Println()

	repoDesc, artifactListIO, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Manifest Desriptor: ", repoDesc)
	buf := new(bytes.Buffer)
	buf.ReadFrom(artifactListIO)
	fmt.Println("Manifest: ", buf.String())
	artifactListIO.Close()

	artifactReference := reg + "/" + repo.Reference.Repository + "@" + repoDesc.Digest.String()

	//
	// Remote signing using notation
	//
	fmt.Println("\n-----Remote signing using notation-----")
	fmt.Println()

	certTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	certs := []*x509.Certificate{certTuple.Cert}
	notationSigner, err := signer.New(certTuple.PrivateKey, certs)
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

	notationRepo := registry.NewRepository(repo)

	targetDesc, err := notation.Sign(ctx, notationSigner, notationRepo, exampleSignOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully signed")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	//
	// Fetching the referrers of a manifest from registry
	//
	fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	fmt.Println()

	referrersLink := "http://" + reg + "/v2/" + repo.Reference.Repository + "/referrers/" + repoDesc.Digest.String()
	fmt.Println("Referrers Link: ", referrersLink)
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

	//
	// Verifing that the image is signed properly using Local Verification
	//
	fmt.Println("\n-----Verifing that the image is signed properly using Local Verification-----")
	fmt.Println()
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

	if err := createTrustStore(certTuple.Cert); err != nil {
		panic(err)
	}

	notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err)
	}

	remoteVerifyOptions := notation.RemoteVerifyOptions{
		ArtifactReference:    artifactReference,
		MaxSignatureAttempts: 50,
	}

	targetDesc, _, err = notation.Verify(ctx, notationVerifier, notationRepo, remoteVerifyOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	//
	// Adding a SBOM to the repository
	//
	fmt.Println("\n-----Adding a SBOM to the repository-----")

	return err
}

func Fluxcd_demo() error {
	return nil
}

func createTrustStore(cert *x509.Certificate) error {
	dir.UserConfigDir = "tmp"

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/Notation.pem", pubBytes, 0600)
}
