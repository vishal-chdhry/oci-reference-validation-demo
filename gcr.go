package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	gcr_remote "github.com/google/go-containerregistry/pkg/v1/remote"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func GCRCrane() error {
	repo_name := "jimnotarytest.azurecr.io/jim/net-monitor:v1"
	artifact_type := "application/vnd.cncf.notary.signature"

	reference, err := name.ParseReference(repo_name)
	if err != nil {
		panic(err)
	}
	fmt.Println(reference.Name())
	desc, err := crane.Head(repo_name)
	if err != nil {
		panic(err)
	}

	ref, err := gcr_remote.Referrers(reference.Context().Digest(desc.Digest.String()))
	if err != nil {
		panic(err)
	}

	for _, descriptor := range ref.Manifests {
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
	return nil
}
