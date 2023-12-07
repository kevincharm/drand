package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/crypto"
	"github.com/drand/drand/key"
	"github.com/drand/kyber/util/random"
)

func BenchmarkVerifyBeacon(b *testing.B) {
	sch, err := crypto.GetSchemeFromEnv()
	if err != nil {
		b.Fatal(err)
	}

	secret := sch.KeyGroup.Scalar().Pick(random.New())
	public := sch.KeyGroup.Point().Mul(secret, nil)

	prevSig := []byte("My Sweet Previous Signature")

	msg := sch.DigestBeacon(&chain.Beacon{
		PreviousSig: prevSig,
		Round:       16,
	})

	sig, _ := sch.AuthScheme.Sign(secret, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		beacon := &chain.Beacon{
			PreviousSig: prevSig,
			Round:       16,
			Signature:   sig,
		}

		err := sch.VerifyBeacon(beacon, public)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkSignBeacon(b *testing.B) {
	sch, err := crypto.GetSchemeFromEnv()
	if err != nil {
		b.Fatal(err)
	}
	secret := sch.KeyGroup.Scalar().Pick(random.New())
	public := sch.KeyGroup.Point().Mul(secret, nil)

	prevSig := []byte("My Sweet Previous Signature")

	msg := sch.DigestBeacon(&chain.Beacon{
		PreviousSig: prevSig,
		Round:       16,
	})

	var sig []byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, _ = sch.AuthScheme.Sign(secret, msg)
	}
	b.StopTimer()

	beacon := &chain.Beacon{
		PreviousSig: prevSig,
		Round:       16,
		Signature:   sig,
	}
	err = sch.VerifyBeacon(beacon, public)
	if err != nil {
		panic(err)
	}
}

//nolint:lll
func TestVerifyBeacon(t *testing.T) {
	t.Parallel()
	testBeacons := []struct {
		Round   uint64
		PubKey  string
		Sig     string
		PrevSig string
		Scheme  string
	}{
		{
			PubKey: "1d9d105fca7ba7d5b0511571539576373e61b94dc879cf27722240b0f4534a4c0c19db16e529bc9005340fbd8cf6101c3a3125922954d36bb2d9d60b79da8e251c3fd0611f5bcc2471f59ac2789cd181adaf99ed229ad9cfc7dd1d73b0303f280ce2ca2f5d944510bf1f4b0bdc98e811df48b3beff482e0ce4a443909df25e83",
			Scheme: "bls-unchained-on-g1",
			Round:  1,
			Sig:    "24f9bbb4ff6777d7fb17d5de85964fe66973e0f5581f724f16cc5d033ebdc93b14de69cd6a9d10b6a452c114ba7a447a60e287604f4d23e5156c89a773a2dc63",
		},
	}

	for _, beacon := range testBeacons {
		sch, err := crypto.SchemeFromName(beacon.Scheme)
		require.NoError(t, err)
		public, err := key.StringToPoint(sch.KeyGroup, beacon.PubKey)
		require.NoError(t, err)
		sig, err := hex.DecodeString(beacon.Sig)
		require.NoError(t, err)
		prev, err := hex.DecodeString(beacon.PrevSig)
		require.NoError(t, err)
		err = sch.VerifyBeacon(&chain.Beacon{Round: beacon.Round, Signature: sig, PreviousSig: prev}, public)
		require.NoError(t, err)
	}
}
