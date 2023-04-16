package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	flux_client "github.com/fluxcd/pkg/oci/client"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/need-being/go-tree"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/ref"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasReg "oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func ORAS_demo(repo_name string, cert string, artifactType string) error {
	ctx := context.Background()
	fmt.Println("\n-----Setting up local repository-----")
	fmt.Println()
	repo, err := remote.NewRepository(repo_name)
	if err != nil {
		panic(err)
	}

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
	data := make(map[string]interface{})
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		panic(err)
	}

	man := ocispec.Manifest{}
	if err := json.Unmarshal(buf.Bytes(), &man); err != nil {
		return fmt.Errorf("error decoding the payload: %w", err)
	}

	if d := man.Config.Digest; d != "" {
		digest := d
		fmt.Println(digest)
	}

	fmt.Println("Manifest: ", buf.String())
	fmt.Println("Manifest: ", data)
	artifactListIO.Close()

	//
	// Fetching the referrers of a manifest from registry
	//
	fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	fmt.Println()

	if err != nil {
		panic(err)
	}

	// path := repo.Reference.Registry + "/" + repo.Reference.Repository
	// root := tree.New(fmt.Sprintf("%s@%s", path, repoDesc.Digest))

	// err = fetchAllReferrers(ctx, repo, repoDesc, artifactType, root)
	// if err != nil {
	// 	return err
	// }

	// err = tree.Print(root)
	// if err != nil {
	// 	panic(err)
	// }

	results, err := Referrers(ctx, repo, repoDesc)
	if err != nil {
		panic(err)
	}

	var desc ocispec.Descriptor
	for _, ociDesc := range results {
		fmt.Println(ociDesc.ArtifactType, "-", ociDesc.Digest.String())
		if ociDesc.ArtifactType == artifactType {
			desc = ociDesc
		}
	}

	// content.FetchAll(ctx,,desc)
	val, err := fetchBytes(ctx, repo, desc)
	if err != nil {
		panic(err)
	}

	artifact := ocispec.Artifact{}
	if err := json.Unmarshal(val, &artifact); err != nil {
		panic(err)
	}
	fmt.Println(artifact)

	predicate, err := fetchBytes(context.TODO(), repo, artifact.Blobs[0])
	if err != nil {
		panic(err)
	}
	fmt.Println(string(predicate))
	// fmt.Println()

	// artifactReference := repo.Reference.Registry + "/" + repo.Reference.Repository + "@" + artifactDig
	// fmt.Println("Artifact Reference:", artifactReference)

	// notationRepo := registry.NewRepository(repo)

	// policyDocument := trustpolicy.Document{
	// 	Version: "1.0",
	// 	TrustPolicies: []trustpolicy.TrustPolicy{
	// 		{
	// 			Name:                  "test-statement-name",
	// 			RegistryScopes:        []string{"*"},
	// 			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
	// 			TrustStores:           []string{"ca:regctl"},
	// 			TrustedIdentities:     []string{"*"},
	// 		},
	// 	},
	// }

	// if err := createTrustStore(cert); err != nil {
	// 	panic(err)
	// }

	// notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	// if err != nil {
	// 	panic(err)
	// }

	// remoteVerifyOptions := notation.RemoteVerifyOptions{
	// 	ArtifactReference:    artifactReference,
	// 	MaxSignatureAttempts: 50,
	// }

	// targetDesc, _, err := notation.Verify(ctx, notationVerifier, notationRepo, remoteVerifyOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Successfully verified")
	// fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	// fmt.Println("targetDesc Digest:", targetDesc.Digest)
	// fmt.Println("targetDesc Size:", targetDesc.Size)

	// dataStatement, err := extractStatement(ctx, repo, desc)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(dataStatement)
	return err
}

func RegClient_Demo(repo_name string, cert string, artifactType string) error {
	ctx := context.Background()
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

	// rdr, err := client.BlobGet(ctx, repoRefer, repoRefs.Descriptors[0])
	// if err != nil {
	// 	panic(err)
	// }
	// defer rdr.Close()
	// io.Copy(os.Stdout, rdr)

	return err
}

func Flux_Demo(repo_name string, cert string, artifactType string) error {
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
	// fmt.Println()
	// repoReferrers, err := ref.New(repo_name)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Registry: ", repoReferrers.Registry)
	// fmt.Println("Repository: ", repoReferrers.Repository)
	// fmt.Println("Reference: ", repoReferrers.Reference)

	// clientHost := config.Host{
	// 	Name:     repoReferrers.Registry,
	// 	Hostname: repoReferrers.Registry,
	// 	TLS:      config.TLSDisabled,
	// }

	// client := regclient.New(regclient.WithConfigHost(clientHost))

	// //
	// // Fetching the repository from registry
	// //
	// fmt.Println("\n-----Fetching the repository from registry-----")
	// fmt.Println()

	// repoManifest, err := client.ManifestHead(ctx, repoReferrers, regclient.WithManifestCheckReferrers(), regclient.WithManifestChild())
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Manifest Desriptor: ", repoManifest)
	// //
	// // Fetching the referrers of a manifest from registry
	// //
	// fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	// fmt.Println()

	// repoRefs, err := client.ReferrerList(ctx, repoReferrers)
	// if err != nil {
	// 	panic(err)
	// }
	// op, err := repoRefs.MarshalPretty()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(string(op))
	// fmt.Println(repoRefs.Descriptors[0])

	// repoDig := repoManifest.GetDescriptor().Digest.String()
	// artifactReference := repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + repoDig

	// //
	// // Verifing that the image is signed properly using Local Verification
	// //
	// fmt.Println("\n-----Verifing the base image is signed properly using Local Verification-----")
	// fmt.Println()
	// fmt.Println("Artifact Reference:", artifactReference)

	// repo, err := remote.NewRepository(repo_name)
	// if err != nil {
	// 	panic(err)
	// }
	// repo.PlainHTTP = true
	// notationRepo := registry.NewRepository(repo)

	// policyDocument := trustpolicy.Document{
	// 	Version: "1.0",
	// 	TrustPolicies: []trustpolicy.TrustPolicy{
	// 		{
	// 			Name:                  "test-statement-name",
	// 			RegistryScopes:        []string{"*"},
	// 			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
	// 			TrustStores:           []string{"ca:regctl"},
	// 			TrustedIdentities:     []string{"*"},
	// 		},
	// 	},
	// }

	// if err := createTrustStore(cert); err != nil {
	// 	panic(err)
	// }

	// notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	// if err != nil {
	// 	panic(err)
	// }

	// remoteVerifyOptions := notation.RemoteVerifyOptions{
	// 	ArtifactReference:    artifactReference,
	// 	MaxSignatureAttempts: 50,
	// }

	// targetDesc, _, err := notation.Verify(ctx, notationVerifier, notationRepo, remoteVerifyOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Successfully verified")
	// fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	// fmt.Println("targetDesc Digest:", targetDesc.Digest)
	// fmt.Println("targetDesc Size:", targetDesc.Size)

	// //
	// // Verifying the attached artifacts
	// //

	// fmt.Println("\n-----Verifying the attached artifacts-----")
	// fmt.Println()
	// descs := repoRefs.Descriptors
	// sbomDig := ""
	// for _, v := range descs {
	// 	if v.ArtifactType == artifactType {
	// 		fmt.Println(v)
	// 		sbomDig = v.Digest.String()
	// 	}
	// }
	// artifactReference = repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + sbomDig
	// fmt.Println(artifactReference)
	// remoteVerifyOptions = notation.RemoteVerifyOptions{
	// 	ArtifactReference:    artifactReference,
	// 	MaxSignatureAttempts: 50,
	// }

	// targetDesc, _, err = notation.Verify(ctx, notationVerifier, notationRepo, remoteVerifyOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Successfully verified")
	// fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	// fmt.Println("targetDesc Digest:", targetDesc.Digest)
	// fmt.Println("targetDesc Size:", targetDesc.Size)

	// fmt.Println("\n-----Fetching the manifest of the attached artifacts and creating a statement-----")
	// fmt.Println()

	// repoRefer, err := ref.New(repoReferrers.Registry + "/" + repoReferrers.Repository + "@" + targetDesc.Digest.String())
	// if err != nil {
	// 	panic(err)
	// }

	// repoManifest, err = client.ManifestGet(ctx, repoRefer)
	// if err != nil {
	// 	panic(err)
	// }
	// maniBytes, err := repoManifest.RawBody()

	// data := make(map[string]interface{})
	// if err := json.Unmarshal(maniBytes, &data); err != nil {
	// 	panic(err)
	// }
	// fmt.Println()
	// fmt.Println(data)

	// rdr, err := client.BlobGet(ctx, repoRefer, repoRefs.Descriptors[0])
	// if err != nil {
	// 	panic(err)
	// }
	// defer rdr.Close()
	// io.Copy(os.Stdout, rdr)

	return err
}

func AzureRegClient_Demo() error {
	ctx := context.Background()
	fmt.Println("\n-----Setting up local repository-----")
	fmt.Println()
	repoReferrers, err := ref.New("jimnotarytest.azurecr.io/jim/net-monitor:v1")
	if err != nil {
		panic(err)
	}

	fmt.Println("Registry: ", repoReferrers.Registry)
	fmt.Println("Repository: ", repoReferrers.Repository)
	fmt.Println("Reference: ", repoReferrers.Reference)

	clientHost := config.Host{
		Name:     repoReferrers.Registry,
		Hostname: repoReferrers.Registry,
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

	return err
}

func createTrustStore(cert string) error {
	dir.UserConfigDir = "tmp"

	if err := os.MkdirAll("tmp/truststore/x509/ca/regctl", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/regctl/regclient.crt", []byte(cert), 0600)
}

func fetchAllReferrers(ctx context.Context, repo oras.ReadOnlyGraphTarget, desc ocispec.Descriptor, artifactType string, node *tree.Node) error {
	results, err := Referrers(ctx, repo, desc)
	if err != nil {
		return err
	}

	for _, r := range results {
		// Find all indirect referrers
		referrerNode := node.AddPath(r.ArtifactType, r.Digest)
		err := fetchAllReferrers(
			ctx, repo,
			ocispec.Descriptor{
				Digest:    r.Digest,
				Size:      r.Size,
				MediaType: r.MediaType,
			},
			artifactType, referrerNode)
		if err != nil {
			return err
		}
	}
	return nil
}

func Referrers(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var results []ocispec.Descriptor
	if repo, ok := src.(orasReg.ReferrerLister); ok {
		// get referrers directly
		err := repo.Referrers(ctx, desc, "", func(referrers []ocispec.Descriptor) error {
			results = append(results, referrers...)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return results, nil
	}
	predecessors, err := src.Predecessors(ctx, desc)
	if err != nil {
		return nil, err
	}
	for _, node := range predecessors {
		fetched, err := fetchBytes(ctx, src, node)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(fetched))
		switch node.MediaType {
		case ocispec.MediaTypeArtifactManifest, ocispec.MediaTypeImageManifest:
			results = append(results, node)
		}
	}
	return results, nil
}

func extractStatement(ctx context.Context, repo *remote.Repository, targetDesc ocispec.Descriptor) (map[string]interface{}, error) {
	fmt.Printf("%+v\n", repo)
	_, artifactListIO, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(artifactListIO)
	if err != nil {
		return nil, err
	}

	manifest := ocispec.Manifest{}
	if err := json.Unmarshal(buf.Bytes(), &manifest); err != nil {
		return nil, fmt.Errorf("error decoding the payload: %w", err)
	}

	data := make(map[string]interface{})
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		return nil, err
	}
	return data, nil
}

func fetchBytes(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return content.ReadAll(rc, desc)
}
