package oci

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func ORAS_demo() error {
	ctx := context.Background()

	fmt.Println("Setting up local repository")
	reg := "localhost:4400"
	repo, err := remote.NewRepository(reg + "/hello-world")
	if err != nil {
		panic(err)
	}
	repo.PlainHTTP = true
	fmt.Println("Repo: ", repo.Reference.Repository)

	// Authentication, if required
	fmt.Println("Setting up Authentication, if required")
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
	fmt.Println("Done.")

	// Seting up source repository to pull from
	fmt.Println("Setting up source repository to pull from")
	src, err := remote.NewRepository("ghcr.io/oci-playground/hello-world")
	if err != nil {
		panic(err)
	}
	fmt.Println("Repo: ", src.Reference.Repository)

	// Pulling from source to local repository
	fmt.Println("Pulling from source to local repository")
	repoDescriptor, err := oras.Copy(ctx, src, "latest", repo, "latest", oras.DefaultCopyOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Digest: ", repoDescriptor.Digest.String())

	// Fetch using the digest
	fmt.Println("Fetch using the digest")
	repoDescriptor, readCloser, err := oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Digest: ", repoDescriptor.Digest.String())
	buf := new(bytes.Buffer)
	buf.ReadFrom(readCloser)
	fmt.Println("Manifest: ", buf.String())
	readCloser.Close()

	artifactReference := "localhost:4400/hello-world@sha256:34b7abc75bb574d97e93d23cdd13ed92b39ee6661a221a8fdcfa57cff8e80f4c"

	// Sign the image using notation
	fmt.Println("Sign the image using notation")
	certTuple := testhelper.GetRSASelfSignedSigningCertTuple("local signing using notation")
	certs := []*x509.Certificate{certTuple.Cert}
	signatureMediaType := cose.MediaTypeEnvelope

	notationSigner, err := signer.New(certTuple.PrivateKey, certs)
	if err != nil {
		panic(err)
	}

	signOptions := notation.RemoteSignOptions{
		SignOptions: notation.SignOptions{
			ArtifactReference:  artifactReference,
			SignatureMediaType: signatureMediaType,
		},
	}

	remoteRepo, err := remote.NewRepository(artifactReference)
	if err != nil {
		panic(err)
	}
	remoteRepo.PlainHTTP = true

	exampleRepo := registry.NewRepository(remoteRepo)

	targetDesc, err := notation.Sign(ctx, notationSigner, exampleRepo, signOptions)
	if err != nil {
		panic(err)
	}

	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	// Fetch the signed image using ORAS
	fmt.Println("Fetch the signed image using ORAS")
	repoDescriptor, readCloser, err = oras.Fetch(ctx, repo, repoDescriptor.Digest.String(), oras.DefaultFetchOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Digest: ", repoDescriptor.Digest.String())

	buf = new(bytes.Buffer)
	buf.ReadFrom(readCloser)
	fmt.Println("Manifest: ", buf.String())

	readCloser.Close()

	// Verify that the image is signed properly using Local Verification
	fmt.Println("Verify that the image is signed properly using Local Verification")

	// policyDocument := trustpolicy.Document{
	// 	Version: "1.0",
	// 	TrustPolicies: []trustpolicy.TrustPolicy{
	// 		{
	// 			Name:                  "test-statement-name",
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
