/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package pubkeypin provides primitives for x509 public key pinning in the
// style of RFC7469.
package pubkeypin

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// Set is a set of pinned x509 public keys.
type Set struct {
	sha256Hashes [][]byte
}

// NewSet returns a new, empty PubKeyPinSet
func NewSet() *Set {
	return &Set{}
}

// Allow adds an allowed public key hash to the Set
func (s *Set) Allow(pubKeyHashes ...string) error {
	for _, pubKeyHash := range pubKeyHashes {
		pubKeyHashBytes, err := hex.DecodeString(pubKeyHash)
		if err != nil {
			return fmt.Errorf("invalid public key hash: %v", err)
		}
		if len(pubKeyHashBytes) != sha256.Size {
			return fmt.Errorf("invalid public key hash (expected a %d byte SHA-256 hash, found %d bytes)", sha256.Size, len(pubKeyHashBytes))
		}
		s.sha256Hashes = append(s.sha256Hashes, pubKeyHashBytes)
	}
	return nil
}

// Check if a certificate matches one of the public keys in the set
func (s *Set) Check(certificate *x509.Certificate) error {
	actualHash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)

	for _, pinnedHash := range s.sha256Hashes {
		if bytes.Equal(actualHash[:], pinnedHash) {
			return nil
		}
	}
	return fmt.Errorf("public key %s not pinned", hex.EncodeToString(actualHash[:]))
}

// Empty returns true if the Set contains no pinned public keys.
func (s *Set) Empty() bool {
	return len(s.sha256Hashes) == 0
}

// Hash calculates the SHA-256 hash of the Subject Public Key Information (SPKI)
// object in an x509 certificate (in DER encoding). It returns the full hash as a
// hex encoded string (suitable for passing to Set.Allow).
func Hash(certificate *x509.Certificate) string {
	spkiHash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(spkiHash[:])
}
