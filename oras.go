package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func ORAS(repo_name string, cert string, artifactType string) error {
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
	fmt.Println()

	return err
}
