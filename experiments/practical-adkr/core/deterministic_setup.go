package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"os"
)

func benchmarkSeed() string {
	return os.Getenv("RLADKR_RANDOM_SEED")
}

func setupECDSAKey(seed, role string, id int) (*ecdsa.PrivateKey, error) {
	if seed == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	curve := elliptic.P256()
	order := curve.Params().N
	d := deterministicScalar(seed, role, id, order)
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func setupEd25519Key(seed, role string, id int) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if seed == "" {
		return ed25519.GenerateKey(rand.Reader)
	}
	material := deterministicBytes(seed, role, id, 32)
	sk := ed25519.NewKeyFromSeed(material)
	return sk.Public().(ed25519.PublicKey), sk, nil
}

func deterministicScalar(seed, role string, id int, order *big.Int) *big.Int {
	max := new(big.Int).Sub(order, big.NewInt(1))
	x := new(big.Int).SetBytes(deterministicBytes(seed, role, id, 32))
	x.Mod(x, max)
	x.Add(x, big.NewInt(1))
	return x
}

func deterministicBytes(seed, role string, id int, size int) []byte {
	out := make([]byte, 0, size)
	var counter uint64
	for len(out) < size {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write([]byte{0})
		h.Write([]byte(role))
		h.Write([]byte{0})
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[:8], uint64(id))
		binary.BigEndian.PutUint64(buf[8:], counter)
		h.Write(buf[:])
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:size]
}
