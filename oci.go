package main

import (
	"context"
	"fmt"
	"os"

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
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	if err := generateTrustStore(); err != nil {
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

	return err
}

func createTrustStore(cert string) error {
	dir.UserConfigDir = "tmp"

	if err := os.MkdirAll("tmp/truststore/x509/ca/regctl", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/regctl/regclient.crt", []byte(cert), 0600)
}

func generateTrustStore() error {
	dir.UserConfigDir = "tmp"
	exampleX509Certificate := `-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgICAKgwDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3Rhcnkx
DzANBgNVBAMTBnJlZ2N0bDAeFw0yMzAzMjExNDA2NDhaFw0yMzAzMjIxNDA2NDha
ME4xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEP
MA0GA1UEChMGTm90YXJ5MQ8wDQYDVQQDEwZyZWdjdGwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCXSp/2i0OCWITNvl4ZzHxPsoJboJ6Z7sFYDJcEBuhL
vpu/M3QPfPeBIMEBFaz+dFFuYapThWoqAGOBLbYWR8a67enVA2alxb+tw/WaBh3j
FE0OZcBCNpYS9cLlabvz3a7cqSiEwo80bMkVZebyoG95nn+fbYZMBZ1kGdMj1DTz
oP2x88hUcsAp6X16Ft/WObvIfjzzcDO1G+mzy640aB4EFY8DGjEeLPNipNBz7R6s
VKvgBbFvq2PiLJSWJCDxE0NhJmtQ+8WkkKNBO+0kWm7OEF7K0c7MZMnP4ryppNXW
uCL4b7dnw1xnhCmW+kgA4O/7ty//4ujtt+y3ixKLOquNAgMBAAGjJzAlMA4GA1Ud
DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
AQEAN73sjy1EiIak4rvnHfsTw+C48Vvq30QOtfAI5oAmK/dtWn8XdADs8ED4p006
EPEgENM3VcQliTsEqcXcfD3AsovIzEoDBmQRMNMM3VXwTkkiX3Fj94e3EyiYblFq
1phRSNJqKvunPoJTvp8uVe3tneuebzBStIcIWs+nbbwvjY5YsGJPHVi0DXLqXOXI
Fj6QtMkOBOcY6TOrYYp2dlxNSL/gseFSFbHRDezr10FRdR618VHVsUK+jdra/yq3
jfDAvxznLLz83LtbnPQrVC+UHFfKCghlgoddnxzkd1NqZdp33tG8XWLpbTzXwZBc
V4bGrIDNf8PSkOkRygkfNM9spw==
-----END CERTIFICATE-----`

	// Adding the certificate into the trust store.
	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationExample.pem", []byte(exampleX509Certificate), 0600)
}
