package encryption

import (
	"crypto/rand"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/google/go-github/v65/github"
	"golang.org/x/crypto/nacl/box"
)

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

func EncryptSecretWithPublicKey(publicKey *github.PublicKey, secretName string, secretValue string) (*github.EncryptedSecret, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.DecodeString was unable to decode public key: %v", err)
	}

	var boxKey [32]byte
	copy(boxKey[:], decodedPublicKey)
	secretBytes := []byte(secretValue)
	encryptedBytes, err := box.SealAnonymous([]byte{}, secretBytes, &boxKey, crypto_rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box.SealAnonymous failed with error %w", err)
	}

	encryptedString := base64.StdEncoding.EncodeToString(encryptedBytes)
	keyID := publicKey.GetKeyID()
	encryptedSecret := &github.EncryptedSecret{
		Name:           secretName,
		KeyID:          keyID,
		EncryptedValue: encryptedString,
	}
	return encryptedSecret, nil
}
