package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/knox-networks/knox-go/signer"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Skip("not implemented")
}

func TestGetPrivateKey(t *testing.T) {
	cm := cryptoManager{}
	mnemonic, _ := cm.GenerateMnemonic()
	kp, _ := cm.GenerateKeyPair(mnemonic)
	if kp.MasterPrivateKey == nil {
		t.Errorf("Expected private key, got nil")
	}
	relations := []signer.VerificationRelation{signer.AssertionMethod, signer.Authentication, signer.CapabilityDelegation, signer.CapabilityInvocation, signer.Master}

	for _, relation := range relations {
		private := kp.GetPrivateKey(relation)

		if !bytes.Equal(private, kp.MasterPrivateKey) {
			t.Errorf("Expected %s, got %s", kp.MasterPrivateKey, private)
		}
	}

}

func TestGetPublicKey(t *testing.T) {
	cm := cryptoManager{}
	mnemonic, _ := cm.GenerateMnemonic()
	kp, _ := cm.GenerateKeyPair(mnemonic)
	if kp.MasterPrivateKey == nil {
		t.Errorf("Expected private key, got nil")
	}
	relations := []signer.VerificationRelation{signer.AssertionMethod, signer.Authentication, signer.CapabilityDelegation, signer.CapabilityInvocation, signer.Master}

	for _, relation := range relations {
		public, err := kp.GetPublicKey(relation)

		if err != nil {
			t.Errorf("Expected public key, got error: %s", err)
		}

		private := kp.GetPrivateKey(relation)

		signature := ed25519.Sign(private, []byte("test"))
		if !ed25519.Verify(public, []byte("test"), signature) {
			t.Errorf("Expected %s, got %s", relation, public)
		}
	}

}

func TestDecodePrefixed(t *testing.T) {
	cm := cryptoManager{}
	mnemonic, _ := cm.GenerateMnemonic()
	kp, _ := cm.GenerateKeyPair(mnemonic)
	message := []byte("hello")
	key_prefix := "z6Mk"

	if !strings.HasPrefix(kp.MasterPublicKey, key_prefix) {
		t.Errorf("Incorrect Prefix")
	}

	_, decoded_public_key, _ := DecodePrefixed(kp.MasterPublicKey)

	signature := ed25519.Sign(kp.MasterPrivateKey, message)

	is_verified := ed25519.Verify(decoded_public_key, message, signature)

	if !is_verified {
		t.Error("Signature verification failed")
	}

}

func TestKeyPairShouldImplementDynamicSigner(t *testing.T) {
	cm := cryptoManager{}
	mnemonic, _ := cm.GenerateMnemonic()
	kps, _ := cm.GenerateKeyPair(mnemonic)

	var s signer.DynamicSigner = kps

	did := s.GetDid()

	if did != DidPrefix+kps.MasterPublicKey {
		t.Errorf("Expected did:knox:z1x2y3z4, got %s", did)
	}

	signed, _ := s.Sign(signer.AssertionMethod, []byte("test"))

	if signed == nil {
		t.Errorf("Expected signature, got nil")
	}
	public, _ := kps.GetPublicKey(signer.AssertionMethod)
	isVerified := ed25519.Verify(ed25519.PublicKey(public), []byte("test"), signed.ProofValue)

	if !isVerified {
		t.Errorf("Expected signature to be valid")
	}
}
