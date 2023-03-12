package oci

import (
	"context"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func ORAS_demo() error {
	ctx := context.Background()

	println("Setting up local repository")
	reg := "localhost:4400"
	repo, err := remote.NewRepository(reg + "/hello-world")
	if err != nil {
		panic(err)
	}
	repo.PlainHTTP = true
	println("Repo: ", repo.Reference.Repository)

	// Authentication, if required
	println("Setting up Authentication, if required")
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
	println("Done.")

	// Seting up source repository to pull from
	println("Setting up source repository to pull from")
	src, err := remote.NewRepository("ghcr.io/oci-playground/hello-world")
	if err != nil {
		panic(err)
	}
	println("Repo: ", src.Reference.Repository)

	// Pulling from source to local repository
	println("Pulling from source to local repository")
	repoDescriptor, err := oras.Copy(ctx, src, "latest", repo, "latest", oras.DefaultCopyOptions)
	if err != nil {
		panic(err)
	}
	println("Data: ", repoDescriptor.Data)
	println("Digest: ", repoDescriptor.Digest.String())

	// Fetch using the digest
	println("Fetch using the digest")
	repoDescriptor, readCloser, err := oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	println("Data: ", repoDescriptor.Data)
	println("Digest: ", repoDescriptor.Digest.String())
	readCloser.Close()

	// Sign the image using notation
	println("Sign the image using notation")

	// Fetch the signed image using ORAS
	println("Fetch the signed image using ORAS")
	repoDescriptor, readCloser, err = oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	println("Data: ", repoDescriptor.Data)
	println("Digest: ", repoDescriptor.Digest.String())
	readCloser.Close()

	// Verify that the image is signed properly using Local Verification
	println("Verify that the image is signed properly using Local Verification")
	return err
}

func Fluxcd_demo() error {
	return nil
}
