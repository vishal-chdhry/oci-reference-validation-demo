package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	flux_client "github.com/fluxcd/pkg/oci/client"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/ref"
	"oras.land/oras-go/v2/registry/remote"
)

func Flux(repo_name string, cert string, artifactType string) error {
	ctx := context.Background()

	fluxCdOpts := []crane.Option{}
	c := flux_client.NewClient(fluxCdOpts)
	fluxListOpts := flux_client.ListOptions{}
	fluxMetadata, err := c.List(ctx, "jimnotarytest.azurecr.io/jim/net-monitor", fluxListOpts)
	if err != nil {
		panic(err)
	}
	fmt.Println(fluxMetadata)

	for k, v := range fluxMetadata[0].ToAnnotations() {
		fmt.Println("Key: ", k, "Val: ", v)
	}

	fmt.Println("\n-----Setting up local repository-----")
	fmt.Println()
	repoReferrers, err := ref.New(repo_name)
	if err != nil {
		panic(err)
	}

	fmt.Println("Registry: ", repoReferrers.Registry)
	fmt.Println("Repository: ", repoReferrers.Repository)
	fmt.Println("Reference: ", repoReferrers.Reference)

	clientHost := config.Host{
		Name:     repoReferrers.Registry,
		Hostname: repoReferrers.Registry,
		TLS:      config.TLSDisabled,
	}

	client := regclient.New(regclient.WithConfigHost(clientHost))

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
	fmt.Println(repoRefs.Descriptors[0])

	repoDig := repoManifest.GetDescriptor().Digest.String()
	artifactReference := repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + repoDig

	//
	// Verifing that the image is signed properly using Local Verification
	//
	fmt.Println("\n-----Verifing the base image is signed properly using Local Verification-----")
	fmt.Println()
	fmt.Println("Artifact Reference:", artifactReference)

	repo, err := remote.NewRepository(repo_name)
	if err != nil {
		panic(err)
	}
	repo.PlainHTTP = true
	notationRepo := registry.NewRepository(repo)

	policyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
				TrustStores:           []string{"ca:regctl"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	if err := createTrustStore(cert); err != nil {
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
		if v.ArtifactType == artifactType {
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

	fmt.Println("\n-----Fetching the manifest of the attached artifacts and creating a statement-----")
	fmt.Println()

	repoRefer, err := ref.New(repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + targetDesc.Digest.String())
	if err != nil {
		panic(err)
	}

	repoManifest, err = client.ManifestGet(ctx, repoRefer)
	if err != nil {
		panic(err)
	}
	maniBytes, err := repoManifest.RawBody()

	data := make(map[string]interface{})
	if err := json.Unmarshal(maniBytes, &data); err != nil {
		panic(err)
	}
	fmt.Println()
	fmt.Println(data)

	rdr, err := client.BlobGet(ctx, repoRefer, repoRefs.Descriptors[0])
	if err != nil {
		panic(err)
	}
	defer rdr.Close()
	io.Copy(os.Stdout, rdr)

	return err
}
