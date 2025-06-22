package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"log/slog"
	"math/big"
	"sync"
	"time"
)

var tlsCert *tls.Certificate
var tlsLock sync.Mutex

const certLifeTime = 16 * time.Hour

func ProvideTLSCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tlsLock.Lock()
	defer tlsLock.Unlock()

	if tlsCert == nil {
		slog.Default().Info("new cert request for SNI", "serverName", chi.ServerName)

		pk := privateKey()
		cert := genCert(pk)

		tlsCert = &tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  pk,
		}

		go func() {
			sleepTime := certLifeTime - 15*time.Minute
			log.Printf("cert will be renewed in %s", sleepTime)
			time.Sleep(sleepTime)

			tlsLock.Lock()
			defer tlsLock.Unlock()
			slog.Default().Info("certificate is expiring")
			tlsCert = nil
		}()
	}
	return tlsCert, nil
}

func privateKey() *ecdsa.PrivateKey {
	slog.Default().Info("creating new P256 private key")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failure to generate key: %s", err)
	}
	return k
}

func genCert(privateKey *ecdsa.PrivateKey) []byte {
	notBefore := time.Now()
	notAfter := notBefore.Add(certLifeTime)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature

	tp := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	tp.KeyUsage |= x509.KeyUsageCertSign
	tp.IsCA = true

	tp.DNSNames = []string{"localhost"}

	derBytes, err := x509.CreateCertificate(rand.Reader, tp, tp, privateKey.Public(), privateKey)
	if err != nil {
		log.Fatalf("createCertificate(): %s", err)
	}

	return derBytes
}
