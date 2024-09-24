package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// encryptSecret encrypts the secret value using the GitHub public key.
// GitHub uses NaCl (Networking and Cryptography Library) box encryption.
func EncryptSecret(publicKeyBase64 string, secretValue string) (string, error) {
	// Decode the GitHub public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode GitHub public key: %v", err)
	}

	// GitHub uses NaCl (box encryption). Generate a new random key pair for encryption.
	var publicKey [32]byte
	copy(publicKey[:], publicKeyBytes)
	_, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate encryption key pair: %v", err)
	}

	// Encrypt the secret value using NaCl box encryption with the public key
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce for encryption: %v", err)
	}

	encryptedBytes := box.Seal(nonce[:], []byte(secretValue), &nonce, &publicKey, privateKey)

	// Encode the encrypted secret as a base64 string
	encryptedSecretBase64 := base64.StdEncoding.EncodeToString(encryptedBytes)

	return encryptedSecretBase64, nil
}
