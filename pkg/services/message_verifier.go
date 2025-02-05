package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"bytes"

	"github.com/didil/inhooks/pkg/models"
	"github.com/pkg/errors"
)

type MessageVerifier interface {
	Verify(flow *models.Flow, m *models.Message) error
}

type messageVerifier struct {
}

func NewMessageVerifier() MessageVerifier {
	return &messageVerifier{}
}

func (v *messageVerifier) Verify(flow *models.Flow, m *models.Message) error {
	verification := flow.Source.Verification

	if verification == nil {
		// no verification required
		return nil
	}

	if verification.VerificationType == models.VerificationTypeHMAC {

		var timestamp, signature, msgContent []byte

                signatureHeader := []byte(m.HttpHeaders.Get(verification.SignatureHeader))
		// Verkada case - the signature in the header is a compound string.
                // split signature into two pieces, separated by '|'
                // first piece is an epoch timestamp, second piece is the HMAC signature
                if bytes.IndexByte(signatureHeader, '|') != -1 {

	                timestamp = signatureHeader[:bytes.IndexByte(signatureHeader, '|')]
			signature = signatureHeader[bytes.IndexByte(signatureHeader, '|')+1:]

			msgContent = append(m.Payload, '|')
	                msgContent = append(msgContent, timestamp...)
			fmt.Printf("signatureHeader: %s\n", signatureHeader)
			fmt.Printf("signedString: %s\n", msgContent)
		} else {
			// if we aren't doing this for Verkada, just use the payload as is.
			msgContent = m.Payload
			signature = []byte(m.HttpHeaders.Get(verification.SignatureHeader))
		}

		signaturePrefix := verification.SignaturePrefix
		algorithm := verification.HMACAlgorithm
		err := v.verifyHMAC(algorithm, signature, signaturePrefix, os.Getenv(verification.CurrentSecretEnvVar), msgContent)

		if err != nil && verification.PreviousSecretEnvVar != "" {
			// try again with previous secret
			err = v.verifyHMAC(algorithm, signature, signaturePrefix, os.Getenv(verification.PreviousSecretEnvVar), msgContent)
		}

		if err != nil {
			return errors.Wrapf(err, "failed to verify message")
		}
	}

	return nil
}

func (v *messageVerifier) verifyHMAC(hmacAlgorithm *models.HMACAlgorithm, signature []byte, signaturePrefix string, secret string, msgContent []byte) error {
	var hashFunc func() hash.Hash

	if hmacAlgorithm == nil {
		return errors.New("no hmac algorithm specified")
	}

	switch *hmacAlgorithm {
	case models.HMACAlgorithmSHA256:
		hashFunc = sha256.New
	default:
		return fmt.Errorf("unexpected hmac algorithm: %s", *hmacAlgorithm)
	}

	mac := hmac.New(hashFunc, []byte(secret))
	_, err := mac.Write(msgContent)
	if err != nil {
		return errors.Wrapf(err, "failed to write hash")
	}
	calculatedMACHex := hex.EncodeToString(mac.Sum(nil))

	if signaturePrefix != "" {
		// add prefix if needed (for github for example, the prefix is 'sha256=')
		calculatedMACHex = signaturePrefix + string(calculatedMACHex)
	}

	if !hmac.Equal([]byte(calculatedMACHex), signature) {
		return errors.New("invalid signature")
	}

	return nil
}
