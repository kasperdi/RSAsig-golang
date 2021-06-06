package main

import (
	"math/big"
	"testing"
	"crypto/rand"
	"reflect"
)

func BenchmarkRSAKeygen3072(b *testing.B) {
	for i := 0; i < b.N; i++ {	
		KeyGen(3072)
	}
}

func BenchmarkRSASign3072bitkey(b *testing.B) {
	_, SK := KeyGen(3072)
	message := make([]byte, 32)
	rand.Read(message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Sign(message, SK)
	}
}

func BenchmarkRSAVerify3072bitkey(b *testing.B) {
	PK, SK := KeyGen(3072)
	message := make([]byte, 32)
	rand.Read(message)
	sig := Sign(message, SK)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Validate(sig, message, PK)
	}

}

func BenchmarkRSAKeygen7680(b *testing.B) {
	for i := 0; i < b.N; i++ {	
		KeyGen(7680)
	}
}

func BenchmarkRSASign7680bitkey(b *testing.B) {
	_, SK := KeyGen(7680)
	message := make([]byte, 32)
	rand.Read(message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Sign(message, SK)
	}
}

func BenchmarkRSAVerify7680bitkey(b *testing.B) {
	PK, SK := KeyGen(7680)
	message := make([]byte, 32)
	rand.Read(message)
	sig := Sign(message, SK)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Validate(sig, message, PK)
	}

}

func BenchmarkRSAKeygen15360(b *testing.B) {
	for i := 0; i < b.N; i++ {	
		KeyGen(15360)
	}
}

func BenchmarkRSASign15360bitkey(b *testing.B) {
	_, SK := KeyGen(15360)
	message := make([]byte, 32)
	rand.Read(message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Sign(message, SK)
	}
}

func BenchmarkRSAVerify15360bitkey(b *testing.B) {
	PK, SK := KeyGen(15360)
	message := make([]byte, 32)
	rand.Read(message)
	sig := Sign(message, SK)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {	
		Validate(sig, message, PK)
	}

}

func Test_gcd(t *testing.T) {
	type args struct {
		m *big.Int
		n *big.Int
	}
	tests := []struct {
		name string
		args args
		want *big.Int
	}{
		{
			args: args{
				m: big.NewInt(10),
				n: big.NewInt(5),
			},
			want: big.NewInt(5),
		},
		{
			args: args{
				m: big.NewInt(12),
				n: big.NewInt(8),
			},
			want: big.NewInt(4),
		},
		{
			args: args{
				m: big.NewInt(31),
				n: big.NewInt(101),
			},
			want: big.NewInt(1),
		},
		{
			args: args{
				m: big.NewInt(7907),
				n: big.NewInt(7919),
			},
			want: big.NewInt(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gcd(tt.args.m, tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("gcd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_calculatep1q1(t *testing.T) {
	type args struct {
		p *big.Int
		q *big.Int
	}
	tests := []struct {
		name string
		args args
		want *big.Int
	}{
		{
			args: args{
				p: big.NewInt(11),
				q: big.NewInt(5),
			},
			want: big.NewInt(40),
		},
		{
			args: args{
				p: big.NewInt(31),
				q: big.NewInt(3),
			},
			want: big.NewInt(60),
		},
		{
			args: args{
				p: big.NewInt(5113),
				q: big.NewInt(4951),
			},
			want: big.NewInt(25304400),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculatep1q1(tt.args.p, tt.args.q); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("calculatep1q1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkPrimePairUsability(t *testing.T) {
	type args struct {
		p *big.Int
		q *big.Int
		e *big.Int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			args: args{
				p: big.NewInt(3),
				q: big.NewInt(11),
				e: big.NewInt(3),
			},
			want: true,
		},
		{
			args: args{
				p: big.NewInt(11),
				q: big.NewInt(3),
				e: big.NewInt(3),
			},
			want: true,
		},
		{
			args: args{
				p: big.NewInt(3),
				q: big.NewInt(5),
				e: big.NewInt(3),
			},
			want: true,
		},
		{
			args: args{
				p: big.NewInt(11),
				q: big.NewInt(11),
				e: big.NewInt(3),
			},
			want: false,
		},
		{
			args: args{
				p: big.NewInt(5),
				q: big.NewInt(7),
				e: big.NewInt(3),
			},
			want: false,
		},
		{
			args: args{
				p: big.NewInt(1091),
				q: big.NewInt(1093),
				e: big.NewInt(3),
			},
			want: false,
		},
		{
			args: args{
				p: big.NewInt(1091),
				q: big.NewInt(1093),
				e: big.NewInt(11),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPrimePairUsability(tt.args.p, tt.args.q, tt.args.e); got != tt.want {
				t.Errorf("checkPrimePairUsability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyGen_ModulusLength(t *testing.T) {
	k := 2048
	publicKey, _ := KeyGen(k)
	actual := publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

	k = 208
	publicKey, _ = KeyGen(k)
	actual = publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

	k = 101
	publicKey, _ = KeyGen(k)
	actual = publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

	k = 40
	publicKey, _ = KeyGen(k)
	actual = publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

	k = 23
	publicKey, _ = KeyGen(k)
	actual = publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

	k = 12
	publicKey, _ = KeyGen(k)
	actual = publicKey.N.BitLen()
	if actual != k {
		t.Errorf("Key has wrong length: Want %d, Got %d", k, actual)
	}

}

func TestSignValidateText(t *testing.T) {
	pk, sk := KeyGen(2048)
	msg := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	signature := Sign([]byte(msg), sk)

	if !Validate(signature, []byte(msg), pk) {
		t.Errorf("Expected accept, but rejected")
	}

	fakeMsg := "To be, or not to be, that is the question."
	if Validate(signature, []byte(fakeMsg), pk) {
		t.Errorf("Expected rejection of msg, but accepted")
	}
}

func TestSignValidateTextSameLength(t *testing.T) {
	pk, sk := KeyGen(2048)
	msg := "To be, or not to be, that is the question."
	signature := Sign([]byte(msg), sk)

	if !Validate(signature, []byte(msg), pk) {
		t.Errorf("Expected accept, but rejected")
	}

	fakeMsg := "to be, or not to be, that is the question."
	if Validate(signature, []byte(fakeMsg), pk) {
		t.Errorf("Expected rejection of msg, but accepted")
	}
}

func TestSignValidate(t *testing.T) {
	for i := 1; i < 4; i++ {
		// Generate key
		pk, sk := KeyGen(2048)
		for j := 1; j < 100; j++ {
			// Generate AES key
			msg := big.NewInt(int64(j))
			signature := Sign(msg.Bytes(), sk)
			if !Validate(signature, msg.Bytes(), pk) {
				t.Errorf("Expected accept, but rejected")
			}
			fakeMsg := big.NewInt(int64(j + 1))
			if Validate(signature, fakeMsg.Bytes(), pk) {
				t.Errorf("Expected rejection of msg, but accepted")
			}
			fakeMsg2 := big.NewInt(int64(j - 1))
			if Validate(signature, fakeMsg2.Bytes(), pk) {
				t.Errorf("Expected rejection of msg, but accepted")
			}
		}
	}
}
