package crypto

import (
	"testing"

	"github.com/knox-networks/knox-go/signer"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Skip("not implemented")
}

func TestKeyPairShouldImplementDynamicSigner(t *testing.T) {

	kps, _ := GenerateKeyPair()

	var s signer.DynamicSigner = kps

	did := s.GetDid()

	if did != DID_PREFIX+kps.MasterPublicKey {
		t.Errorf("Expected did:knox:z1x2y3z4, got %s", did)
	}

	signature, _ := s.Sign(signer.AssertionMethod, []byte("test"))

	if signature == nil {
		t.Errorf("Expected signature, got nil")
	}

}
