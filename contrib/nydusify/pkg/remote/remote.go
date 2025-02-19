// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/remotes"
	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Remote provides the ability to access remote registry
type Remote struct {
	// `Ref` is pointing to a remote image in formatted string host[:port]/[namespace/]repo[:tag]
	Ref    string
	parsed reference.Named
	// The resolver is used for image pull or fetches requests. The best practice
	// in containerd is that each resolver instance is used only once for a request
	// and is destroyed when the request completes. When a registry token expires,
	// the resolver does not re-apply for a new token, so it's better to create a
	// new resolver instance using resolverFunc for each request.
	resolverFunc func(insecure bool) remotes.Resolver
	pushed       sync.Map

	retryWithHTTP bool
}

// New creates remote instance from docker remote resolver
func New(ref string, resolverFunc func(bool) remotes.Resolver) (*Remote, error) {
	parsed, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, err
	}

	return &Remote{
		Ref:          ref,
		parsed:       parsed,
		resolverFunc: resolverFunc,
	}, nil
}

func (remote *Remote) MaybeWithHTTP(err error) {
	parsed, _ := reference.ParseNormalizedNamed(remote.Ref)
	if parsed != nil {
		host := reference.Domain(parsed)
		// If the error message includes the current registry host string, it
		// implies that we can retry the request with plain HTTP.
		if strings.Contains(err.Error(), fmt.Sprintf("/%s/", host)) {
			remote.retryWithHTTP = true
		}
	}
}

func (remote *Remote) IsWithHTTP() bool {
	return remote.retryWithHTTP
}

// Push pushes blob to registry
func (remote *Remote) Push(ctx context.Context, desc ocispec.Descriptor, byDigest bool, reader io.Reader) error {
	// Concurrently push blob with same digest using containerd
	// docker remote client will cause error:
	// `failed commit on ref: unexpected size x, expected y`
	// use ref key leveled mutex lock to avoid the issue.
	refKey := remotes.MakeRefKey(ctx, desc)
	lock, _ := remote.pushed.LoadOrStore(refKey, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	pusher, err := remote.resolverFunc(remote.retryWithHTTP).Pusher(ctx, ref)
	if err != nil {
		return err
	}

	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer writer.Close()

	return content.Copy(ctx, writer, reader, desc.Size, desc.Digest)
}

// Pull pulls blob from registry
func (remote *Remote) Pull(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadCloser, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	puller, err := remote.resolverFunc(remote.retryWithHTTP).Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}

	reader, err := puller.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	return reader, nil
}

// Resolve parses descriptor for given image reference
func (remote *Remote) Resolve(ctx context.Context) (*ocispec.Descriptor, error) {
	ref := reference.TagNameOnly(remote.parsed).String()

	// Create a new resolver instance for the request
	_, desc, err := remote.resolverFunc(remote.retryWithHTTP).Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	return &desc, nil
}

// dockerConfig represents docker's ~/.docker/config.json file
type dockerConfig struct {
	AuthConfigs map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

// getDockerCredentials retrieves authentication info from docker config
func (remote *Remote) getDockerCredentials() (string, error) {
	configPath := os.Getenv("DOCKER_CONFIG")
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.Wrap(err, "get user home directory")
		}
		configPath = filepath.Join(home, ".docker", "config.json")
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No docker config is not an error
		}
		return "", errors.Wrap(err, "read docker config")
	}

	var config dockerConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return "", errors.Wrap(err, "parse docker config")
	}

	host := reference.Domain(remote.parsed)
	// Handle docker hub special case
	if host == "registry-1.docker.io" {
		host = "https://index.docker.io/v1/"
	}

	if auth, ok := config.AuthConfigs[host]; ok {
		return auth.Auth, nil
	}

	return "", nil
}

// Mount attempts to mount a blob from another repository using Registry API
func (remote *Remote) Mount(ctx context.Context, desc ocispec.Descriptor, sourceRef string) error {
	sourceRepo, err := reference.ParseNormalizedNamed(sourceRef)
	if err != nil {
		return errors.Wrapf(err, "parse source reference %s", sourceRef)
	}

	if reference.Path(sourceRepo) == reference.Path(remote.parsed) {
		return nil
	}

	scheme := "https"
	if remote.retryWithHTTP {
		scheme = "http"
	}

	host := reference.Domain(remote.parsed)
	mountURL := fmt.Sprintf("%s://%s/v2/%s/blobs/uploads/?mount=%s&from=%s",
		scheme,
		host,
		reference.Path(remote.parsed),
		desc.Digest.String(),
		reference.Path(sourceRepo),
	)

	req, err := http.NewRequestWithContext(ctx, "POST", mountURL, nil)
	if err != nil {
		return errors.Wrap(err, "create request")
	}

	// Handle authentication
	auth, err := remote.getDockerCredentials()
	if err != nil {
		logrus.Warnf("Failed to get docker credentials: %v", err)
	} else if auth != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "send request")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusAccepted:
		return nil
	case http.StatusUnauthorized:
		authHeader := resp.Header.Get("WWW-Authenticate")
		if authHeader != "" {
			// Try to parse WWW-Authenticate header for better error message
			return errors.Errorf("authentication required: %s", authHeader)
		}
		return errors.New("unauthorized: authentication required")
	case http.StatusNotFound:
		return errdefs.ErrNotFound
	default:
		return errors.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
