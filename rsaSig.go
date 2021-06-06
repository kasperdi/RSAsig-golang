package main

import (
	"crypto/sha256"
	"math/big"
	"crypto/rand"
)

// PK is the public key
type PK struct {
	N *big.Int
	E *big.Int
}

// SK is the secret key
type SK struct {
	N *big.Int
	D *big.Int
}

// KeyGen generates a public key and secret key pair with the modulus being of length k > 3 (when e=3 k should be > 11)
func KeyGen(k int) (PK, SK) {
	p := new(big.Int)
	q := new(big.Int)
	e := big.NewInt(65537) // hardcode e to be 65537

	// generate two usable primes (p, q) of length k/2
	for {
		var err1, err2 error
		p, err1 = rand.Prime(rand.Reader, k/2)
		q, err2 = rand.Prime(rand.Reader, (k+1)/2) // the +1 is for when k is odd
		if err1 != nil {
			panic(err1)
		}
		if err2 != nil {
			panic(err2)
		}

		usable := checkPrimePairUsability(p, q, e)
		if usable {
			break
		}
	}

	// multiply the two primes (N)
	modulo := new(big.Int)
	modulo.Mul(p, q)

	// calculate d
	p1q1 := calculatep1q1(p, q)
	d := new(big.Int)
	d.ModInverse(e, p1q1)

	// create public key and secret key
	pk := PK{N: modulo, E: e}
	sk := SK{N: modulo, D: d}

	return pk, sk
}

// checkPrimePairUsability takes two primes p and q, and an encryption exponent and checks whether they would work together
func checkPrimePairUsability(p *big.Int, q *big.Int, e *big.Int) bool {
	// ensure p and q are different
	if p.Cmp(q) == 0 {
		return false
	}

	// calculate (p-1) * (q-1)
	p1q1 := calculatep1q1(p, q)

	// ensure (p-1)(q-1) and e=3 are coprime
	gcd := gcd(p1q1, e)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false
	}

	return true
}

// calculate (p-1) * (q-1)
func calculatep1q1(p *big.Int, q *big.Int) *big.Int {
	p1q1 := new(big.Int)
	p1 := new(big.Int)
	p1.Sub(p, big.NewInt(1))
	q1 := new(big.Int)
	q1.Sub(q, big.NewInt(1))
	p1q1.Mul(p1, q1)
	return p1q1
}

// gcd implements the Euclidean algorithm
func gcd(m *big.Int, n *big.Int) *big.Int {
	if n.Cmp(big.NewInt(0)) == 0 {
		return m
	}
	r := new(big.Int)
	r.Mod(m, n)
	return gcd(n, r)
}

// Sign hashes the message and signs
// h(m)^d mod n
func Sign(message []byte, sk SK) *big.Int {
	hashedMsg := new(big.Int).SetBytes(HashMessage(message))
	return new(big.Int).Exp(hashedMsg, sk.D, sk.N)
}

// Validate checks that the given signature is a valid signature on the given message, with respect to the provided key
// s^e mod n = h(m)
func Validate(signature *big.Int, message []byte, pk PK) bool {
	if (signature == nil) {
		return false
	}
	hashedMsg := new(big.Int).SetBytes(HashMessage(message))
	return new(big.Int).Exp(signature, pk.E, pk.N).Cmp(hashedMsg) == 0
}

// HashMessage hashes the given bytearray
func HashMessage(message []byte) []byte {
	hash := sha256.New()
	hash.Write(message)
	return hash.Sum(nil)
}
