package tlsutil

import (
	"crypto/rsa"
	"crypto/x509"
	"sync"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type CertType int

const (
	ClientCert CertType = iota
	ServingCert
	ClientAndServingCert
)

// CertConfig configures the Cert generation.
type CertConfig struct {
	// CertName is the name of the cert.
	CertName string
	// Optional
	// CertType is the type of the cert. Can be client, serving, or both; defaults to both.
	CertType CertType
	// CommonName is the common name of the cert and will be added to x509 certificate's CommonName.
	CommonName string
	// Organization is Organization of the cert and will be added to x509 certificate's Organization.
	Organization []string
}

type CA interface {
	// GenerateCert generates a secret containing TLS encryption key and Cert for the given service.
	// When generating the secret, a unique CA for the Custom Resource is also generated to sign the Cert.
	// In addition to generate CA and the Secret, those are also created as the Kubernetes objects with CA format shown in output of the CACert() and with the format of the secret as the following:
	// kind: Secret
	// apiVersion: v1
	// metadata:
	//  name: <cr-kind>-<cr-name>-<cert-name>
	//  namespace: <ns>
	// data:
	//  cert.pem: ..
	//  cert-key.pem: ..
	GenerateCert(cr runtime.Object, service v1.Service, config CertConfig) (*v1.Secret, error)
	// CACert returns the CA cert as in a ConfigMap and the CA encryption key as in a Secret for the given
	// Custom resource(CR); the CA is unique per CR. For example, calling
	// CACert twice returns the same ConfigMap and Secret.
	// The formats for the ConfigMap and Secret are the following:
	// kind: ConfigMap
	//   apiVersion: v1
	//   metadata:
	//     name: <cr-kind>-<cr-name>-ca
	//     namespace: <ns>
	//   data:
	//     ca.pem: ...
	//  kind: Secret
	//  apiVersion: v1
	//  metadata:
	//   name: <cr-kind>-<cr-name>-ca
	//   namespace: <ns>
	//  data:
	//   ca-key.pem: ..
	CACert(cr runtime.Object) (*v1.ConfigMap, *v1.Secret, error)
}

// NewCA creates the CA object. Can make the behavior singleton.
func NewCA() CA {
	return &CAImpl{}
}

type CAImpl struct {
	kcsm sync.Map
	casm sync.Map
}

type keyAndCert struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (ca *CAImpl) GenerateCert(cr runtime.Object, service v1.Service, config CertConfig) (*v1.Secret, error) {
	a := meta.NewAccessor()
	k, err := a.Kind(cr)
	if err != nil {
		return nil, err
	}
	n, err := a.Name(cr)
	if err != nil {
		return nil, err
	}
	ns, err := a.Namespace(cr)
	if err != nil {
		return nil, err
	}

	v, ok := ca.kcsm.Load(k + n + ns + config.CertName)
	var (
		key  *rsa.PrivateKey
		cert *x509.Certificate
	)
	if ok {
		kv := v.(*keyAndCert)
		key = kv.key
		cert = kv.cert
	} else {
		var (
			caKey  *rsa.PrivateKey
			caCert *x509.Certificate
		)
		v, ok := ca.casm.Load(k + n + ns)
		if ok {
			kv := v.(*keyAndCert)
			caKey = kv.key
			caCert = kv.cert
		} else {
			caKey, err := NewPrivateKey()
			if err != nil {
				return nil, err
			}
			caCert, err := NewSelfSignedCACertificate(caKey)
			if err != nil {
				return nil, err
			}
			ca.casm.Store(k+n+ns, &keyAndCert{key: caKey, cert: caCert})
		}

		key, err := NewPrivateKey()
		if err != nil {
			return nil, err
		}
		cert, err := NewSignedCertificate(config, service, key, caCert, caKey)
		if err != nil {
			return nil, err
		}
		ca.kcsm.Store(k+n+ns+config.CertName, &keyAndCert{key: key, cert: cert})
	}

	se := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k + n + config.CertName,
			Namespace: ns,
		},
		Data: map[string][]byte{
			"cert.pem":     EncodeCertificatePEM(cert),
			"cert-key.pem": EncodePrivateKeyPEM(key),
		},
	}
	return se, nil
}

func (ca *CAImpl) CACert(cr runtime.Object) (*v1.ConfigMap, *v1.Secret, error) {
	a := meta.NewAccessor()
	k, err := a.Kind(cr)
	if err != nil {
		return nil, nil, err
	}
	n, err := a.Name(cr)
	if err != nil {
		return nil, nil, err
	}
	ns, err := a.Namespace(cr)
	if err != nil {
		return nil, nil, err
	}

	var (
		caKey  *rsa.PrivateKey
		caCert *x509.Certificate
	)
	v, ok := ca.casm.Load(k + n + ns)
	if !ok {
		caKey, err := NewPrivateKey()
		if err != nil {
			return nil, nil, err
		}
		caCert, err := NewSelfSignedCACertificate(caKey)
		if err != nil {
			return nil, nil, err
		}
		ca.casm.Store(k+n+ns, &keyAndCert{key: caKey, cert: caCert})
	} else {
		kv := v.(*keyAndCert)
		caKey = kv.key
		caCert = kv.cert
	}

	cm := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k + n + "-ca",
			Namespace: ns,
		},
		Data: map[string]string{
			"ca.pem": string(EncodeCertificatePEM(caCert)),
		},
	}
	se := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k + n + "-ca",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"ca-key.pem": EncodePrivateKeyPEM(caKey),
		},
	}
	return cm, se, nil
}
