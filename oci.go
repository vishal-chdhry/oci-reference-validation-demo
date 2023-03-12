package oci

import (
	"context"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

func ORAS_demo() error {
	ctx := context.Background()
	username := "username"
	password := "password"

	// Setting up local repository
	reg := "example.registy.io"
	repo, err := remote.NewRepository(reg + "/myrepo")
	if err != nil {
		panic(err)
	}
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.DefaultCache,
		Credential: auth.StaticCredential(reg, auth.Credential{
			Username: username,
			Password: password,
		}),
	}

	// Seting up source repository to pull from
	src, err := remote.NewRepository(reg + "/source")
	if err != nil {
		panic(err)
	}

	// Pulling from source to local repository
	repoDescriptor, err := oras.Copy(ctx, src, "latest", repo, "latest", oras.DefaultCopyOptions)
	if err != nil {
		panic(err)
	}

	// Fetch using the digest
	repoDescriptor, readCloser, err := oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	readCloser.Close()

	// Sign the image using notation

	// Fetch the signed image using ORAS

	// Verify that the image is signed properly using Local Verification
	return err
}

func Fluxcd_demo() error {
	return nil
}
