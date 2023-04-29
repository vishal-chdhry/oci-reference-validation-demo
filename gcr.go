package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	gcr_remote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"oras.land/oras-go/v2/registry/remote"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func GCRCrane(repo string, certificate string, artifact_type string) error {
	reference, err := name.ParseReference(repo)
	if err != nil {
		panic(err)
	}
	fmt.Println(reference.Name())
	//
	// Fetching the repository from registry
	//
	fmt.Println("\n-----Fetching the repository from registry-----")
	fmt.Println()
	desc, err := crane.Head(repo)
	if err != nil {
		panic(err)
	}

	//
	// Fetching the referrers of a manifest from registry
	//
	ref, err := gcr_remote.Referrers(reference.Context().Digest(desc.Digest.String()))
	if err != nil {
		panic(err)
	}

	refDescs, err := ref.IndexManifest()
	if err != nil {
		panic(err)
	}
	fmt.Println("\n-----Fetching the referrers of a manifest from registry-----")
	fmt.Println()
	for _, descriptor := range refDescs.Manifests {
		fmt.Println("Digest:", descriptor.Digest.String())
		fmt.Println("Artifact Type:", descriptor.ArtifactType)
		if descriptor.ArtifactType == artifact_type {
			ref := reference.Context().RegistryStr() + "/" + reference.Context().RepositoryStr() + "@" + descriptor.Digest.String()
			reference, err := name.ParseReference(ref)
			if err != nil {
				panic(err)
			}

			v1ToOciSpecDescriptor(descriptor)
			manifestBytes, err := crane.Manifest(ref)
			if err != nil {
				panic(err)
			}

			var manifest ocispec.Manifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				panic(err)
			}
			fmt.Println(manifest.Layers)

			predicateRef := reference.Context().RegistryStr() + "/" + reference.Context().RepositoryStr() + "@" + manifest.Layers[0].Digest.String()
			layer, err := crane.PullLayer(predicateRef)
			if err != nil {
				panic(err)
			}

			io, err := layer.Uncompressed()
			if err != nil {
				panic(err)
			}
			buf := new(bytes.Buffer)

			_, err = buf.ReadFrom(io)
			if err != nil {
				panic(err)
			}

			fmt.Println(buf.String())
		}
	}

	//
	// Verifing that the image is signed properly using Local Verification
	//
	fmt.Println("\n-----Verifing the base image is signed properly using Local Verification-----")
	fmt.Println()

	artifact_reference := reference.Context().RegistryStr() + "/" + reference.Context().RepositoryStr() + "@" + desc.Digest.String()
	fmt.Println("Artifact Reference:", artifact_reference)

	// remoteOpts, craneOpts, err := getGCROpts()
	// if err != nil {
	// 	panic(err)
	// }
	// notationRepo := NewRepository(craneOpts, remoteOpts, reference)

	repo_oras, err := remote.NewRepository(repo)
	if err != nil {
		panic(err)
	}
	notationRepo := registry.NewRepository(repo_oras)

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

	if err := createTrustStore(certificate); err != nil {
		panic(err)
	}

	notationVerifier, err := verifier.New(&policyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err)
	}

	remoteVerifyOptions := notation.RemoteVerifyOptions{
		ArtifactReference:    artifact_reference,
		MaxSignatureAttempts: 50,
	}

	targetDesc, _, err := notation.Verify(context.Background(), notationVerifier, notationRepo, remoteVerifyOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)
	return nil
}
