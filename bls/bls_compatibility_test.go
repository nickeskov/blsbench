package bls_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	cbls "github.com/cloudflare/circl/sign/bls"
	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
)

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggSig = blst.P2Aggregate

const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" // ethereum standard domain separation tag

func rand32(t *testing.T) []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func newKeypairBlst(t *testing.T) (*blst.SecretKey, *PublicKey) {
	sk := blst.KeyGen(rand32(t))
	pk := new(PublicKey).From(sk) // G1/P1
	return sk, pk
}

func newKeypairCircl(t *testing.T) (*cbls.PrivateKey[cbls.KeyG1SigG2], *cbls.PublicKey[cbls.KeyG1SigG2]) {
	sk, err := cbls.KeyGen[cbls.KeyG1SigG2](rand32(t), nil, nil)
	require.NoError(t, err)
	pk := sk.PublicKey()
	return sk, pk
}

func TestBlstSignatureVerifyByCircl(t *testing.T) {
	sk1, pk1 := newKeypairBlst(t)
	sk2, pk2 := newKeypairBlst(t)

	msg := []byte("blst -> cirl")

	sig1 := new(Signature).Sign(sk1, msg, []byte(DST))
	sig2 := new(Signature).Sign(sk2, msg, []byte(DST))

	var agg AggSig
	require.True(t, agg.Aggregate([]*Signature{sig1, sig2}, true))
	aggSig := agg.ToAffine()

	// Serialize to standard compressed forms.
	pk1Bytes := pk1.Compress()       // 48 bytes (G1).
	pk2Bytes := pk2.Compress()       // 48 bytes (G1).
	aggSigBytes := aggSig.Compress() // 96 bytes (G2).

	var circlPK1 cbls.PublicKey[cbls.KeyG1SigG2]
	var circlPK2 cbls.PublicKey[cbls.KeyG1SigG2]
	err := circlPK1.UnmarshalBinary(pk1Bytes)
	require.NoError(t, err)
	err = circlPK2.UnmarshalBinary(pk2Bytes)
	require.NoError(t, err)

	ok := cbls.VerifyAggregate[cbls.KeyG1SigG2](
		[]*cbls.PublicKey[cbls.KeyG1SigG2]{&circlPK1, &circlPK2},
		[][]byte{msg, msg},
		aggSigBytes,
	)
	require.True(t, ok)
}

func TestCirclSignatureVerifyByBlst(t *testing.T) {
	sk1, pk1 := newKeypairCircl(t)
	sk2, pk2 := newKeypairCircl(t)

	msg := []byte("circl -> blst")

	sigBytes1 := cbls.Sign[cbls.KeyG1SigG2](sk1, msg)
	sigBytes2 := cbls.Sign[cbls.KeyG1SigG2](sk2, msg)

	// CIRCL aggregates signature bytes (G2)
	aggBytes, err := cbls.Aggregate[cbls.KeyG1SigG2](cbls.G1{}, [][]byte{sigBytes1, sigBytes2})
	require.NoError(t, err)

	// Export CIRCL public key in compressed form (G1, 48B).
	pkBytes1, err := pk1.MarshalBinary()
	require.NoError(t, err)
	var blstPK blst.P1Affine
	require.NotNil(t, blstPK.Uncompress(pkBytes1))
	// Export CIRCL public key in compressed form (G1, 48B).
	pkBytes2, err := pk2.MarshalBinary()
	require.NoError(t, err)
	var blstPK2 blst.P1Affine
	require.NotNil(t, blstPK2.Uncompress(pkBytes2))
	var blstSig blst.P2Affine
	require.NotNil(t, blstSig.Uncompress(sigBytes2))

	// Import aggregated signature into blst.
	var blstAgg blst.P2Affine
	require.NotNil(t, blstAgg.Uncompress(aggBytes))

	okAgg := blstAgg.FastAggregateVerify(true, []*blst.P1Affine{&blstPK, &blstPK2}, msg, []byte(DST))
	fmt.Println("blst.FastAggregateVerify(CIRCL agg sig):", okAgg)
}
