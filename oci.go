package oci

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

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

	// Fetch the repository from registry
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
	artifactReference := reg + "/" + repo.Reference.Repository + "@" + repoDescriptor.Digest.String()
	fmt.Println(artifactReference)

	// policyDocument := trustpolicy.Document{
	// 	Version: "1.0",
	// 	TrustPolicies: []trustpolicy.TrustPolicy{
	// 		{
	// 			Name:                  "trust-policy",
	// 			RegistryScopes:        []string{"example/software"},
	// 			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
	// 			TrustStores:           []string{"ca:valid-trust-store"},
	// 			TrustedIdentities:     []string{"*"},
	// 		},
	// 	},
	// }

	// verifyOptions := notation.VerifyOptions{
	// 	ArtifactReference:  artifactReference,
	// 	SignatureMediaType: signatureMediaType,
	// }

	// exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	// if err != nil {
	// 	panic(err) // Handle error
	// }

	return err
}

func Fluxcd_demo() error {
	return nil
}
