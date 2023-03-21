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
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/ref"
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
	// TODO: Change this implimentation to mimic the working of `oras discover`
	fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	fmt.Println()

	// refs, err := graph.Referrers(ctx, repo, repoDesc, "")

	fmt.Println(targetDesc.Annotations)
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
	fmt.Println("Referrers: ", ref)

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
	// TODO: Add an example SBOM to the repistory, sign it and verify it.
	fmt.Println("\n-----Adding a SBOM to the repository-----")

	return err
}

func RegClient_Demo() error {
	ctx := context.Background()
	fmt.Println("\n-----Setting up local repository-----")
	fmt.Println()
	regName := "localhost:5000"

	clientHost := config.Host{
		Name:     regName,
		Hostname: regName,
		TLS:      config.TLSDisabled,
	}

	client := regclient.New(regclient.WithConfigHost(clientHost))

	repoReferrers, err := ref.New(regName + "/lachie/net-monitor:v1")
	if err != nil {
		panic(err)
	}
	fmt.Println("Registry: ", repoReferrers.Registry)
	fmt.Println("Repository: ", repoReferrers.Repository)
	fmt.Println("Reference: ", repoReferrers.Reference)

	//
	// Fetching the repository from registry
	//
	fmt.Println("\n-----Fetching the repository from registry-----")
	fmt.Println()

	repoManifest, err := client.ManifestHead(ctx, repoReferrers, regclient.WithManifestCheckReferrers(), regclient.WithManifestChild())
	if err != nil {
		panic(err)
	}

	fmt.Println("Manifest Desriptor: ", repoManifest)
	//
	// Fetching the referrers of a manifest from registry
	//
	fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	fmt.Println()

	repoRefs, err := client.ReferrerList(ctx, repoReferrers)
	if err != nil {
		panic(err)
	}
	op, err := repoRefs.MarshalPretty()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(op))

	repoDig := repoManifest.GetDescriptor().Digest.String()
	artifactReference := repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + repoDig

	//
	// Verifing that the image is signed properly using Local Verification
	//
	fmt.Println("\n-----Verifing the base image is signed properly using Local Verification-----")
	fmt.Println()
	fmt.Println("Artifact Reference:", artifactReference)

	repo, err := remote.NewRepository(regName + "/lachie/net-monitor")
	if err != nil {
		panic(err)
	}
	repo.PlainHTTP = true
	notationRepo := registry.NewRepository(repo)

	policyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "trust-policy",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
				TrustStores:           []string{"ca:regctl"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}
	dir.UserConfigDir = "tmp"

	notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err)
	}

	remoteVerifyOptions := notation.RemoteVerifyOptions{
		ArtifactReference:    artifactReference,
		MaxSignatureAttempts: 50,
	}

	targetDesc, _, err := notation.Verify(ctx, notationVerifier, notationRepo, remoteVerifyOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	//
	// Verifying the attached artifacts
	//

	fmt.Println("\n-----Verifying the attached artifacts-----")
	fmt.Println()
	descs := repoRefs.Descriptors
	sbomDig := ""
	for _, v := range descs {
		if v.Annotations["org.opencontainers.artifact.description"] == "CycloneDX JSON SBOM" {
			fmt.Println(v)
			sbomDig = v.Digest.String()
		}
	}
	artifactReference = repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + sbomDig
	fmt.Println(artifactReference)
	remoteVerifyOptions = notation.RemoteVerifyOptions{
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

	return err
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
