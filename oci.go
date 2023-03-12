package oci

import (
	"context"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func ORAS_demo() error {
	ctx := context.Background()

	// Setting up local repository
	reg := "127.0.0.1:4400"
	repo, err := remote.NewRepository(reg + "/hello-world")
	if err != nil {
		panic(err)
	}

	// // Authentication, if required
	// username := "username"
	// password := "password"
	// repo.Client = &auth.Client{
	// 	Client: retry.DefaultClient,
	// 	Cache:  auth.DefaultCache,
	// 	Credential: auth.StaticCredential(reg, auth.Credential{
	// 		Username: username,
	// 		Password: password,
	// 	}),
	// }

	// Seting up source repository to pull from
	src, err := remote.NewRepository("ghcr.io/oci-playground/hello-world")
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
	if err != nil {
		panic(err)
	}
	readCloser.Close()

	// Sign the image using notation

	// Fetch the signed image using ORAS
	repoDescriptor, readCloser, err = oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	readCloser.Close()

	// Verify that the image is signed properly using Local Verification
	return err
}

func Fluxcd_demo() error {
	return nil
}
