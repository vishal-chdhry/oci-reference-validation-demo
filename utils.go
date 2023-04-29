package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/need-being/go-tree"
	"github.com/notaryproject/notation-go/dir"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasReg "oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

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

func v1ToOciSpecDescriptor(v1desc v1.Descriptor) ocispec.Descriptor {
	ociDesc := ocispec.Descriptor{
		MediaType:   string(v1desc.MediaType),
		Digest:      digest.Digest(v1desc.Digest.String()),
		Size:        v1desc.Size,
		URLs:        v1desc.URLs,
		Annotations: v1desc.Annotations,
		Data:        v1desc.Data,

		ArtifactType: v1desc.ArtifactType,
	}
	if v1desc.Platform != nil {
		ociDesc.Platform = &ocispec.Platform{
			Architecture: v1desc.Platform.Architecture,
			OS:           v1desc.Platform.OS,
			OSVersion:    v1desc.Platform.OSVersion,
		}
	}
	return ociDesc
}

func getGCROpts() ([]gcrremote.Option, crane.Option, error) {
	remoteOpts := []gcrremote.Option{}
	var craneOpts crane.Option
	pusher, err := gcrremote.NewPusher(remoteOpts...)
	if err != nil {
		return remoteOpts, craneOpts, err
	}
	remoteOpts = append(remoteOpts, gcrremote.Reuse(pusher))

	puller, err := gcrremote.NewPuller(remoteOpts...)
	if err != nil {
		return remoteOpts, craneOpts, err
	}
	remoteOpts = append(remoteOpts, gcrremote.Reuse(puller))

	return remoteOpts, craneOpts, err
}
