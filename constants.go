package xmlsecurity

import (
	"crypto"
	"crypto/x509"
)

const (
	SpaceDSig         = "ds"
	SpaceXEnc         = "xenc"
	SpaceXEnc11       = "xenc11"
	NamespaceXEnc     = "http://www.w3.org/2001/04/xmlenc#"
	NamespaceXEnc11   = "http://www.w3.org/2009/xmlenc11#"
	NamespaceDSig     = "http://www.w3.org/2000/09/xmldsig#"
	NamespaceDSigMore = "http://www.w3.org/2001/04/xmldsig-more#"

	XEncTypeElement = NamespaceXEnc + "Element"
	XEncTypeContent = NamespaceXEnc + "Content"
	XEncTypeEXI     = NamespaceXEnc11 + "EXI"
)

type DigestAlgorithm string

// Digest algorithms
const (
	DigestSha1      DigestAlgorithm = NamespaceDSig + "sha1"
	DigestSha224    DigestAlgorithm = NamespaceDSigMore + "sha224"
	DigestSha256    DigestAlgorithm = NamespaceXEnc + "sha256"
	DigestSha384    DigestAlgorithm = NamespaceDSigMore + "sha384"
	DigestSha512    DigestAlgorithm = NamespaceXEnc + "sha512"
	DigestRipeMd160 DigestAlgorithm = NamespaceXEnc + "ripemd160"
)

var (
	digestAlgorithms = map[DigestAlgorithm]crypto.Hash{
		DigestSha1:      crypto.SHA1,
		DigestSha224:    crypto.SHA224,
		DigestSha256:    crypto.SHA256,
		DigestSha384:    crypto.SHA384,
		DigestSha512:    crypto.SHA512,
		DigestRipeMd160: crypto.RIPEMD160,
	}

	digestAlgorithmIdentifiers = map[crypto.Hash]DigestAlgorithm{
		crypto.SHA1:      DigestSha1,
		crypto.SHA224:    DigestSha224,
		crypto.SHA256:    DigestSha256,
		crypto.SHA384:    DigestSha384,
		crypto.SHA512:    DigestSha512,
		crypto.RIPEMD160: DigestRipeMd160,
	}
)

/*
# Block Encryption methods

Note: Use of AES GCM is strongly recommended over any CBC block encryption
algorithms as recent advances in cryptanalysis have cast doubt on the
ability of CBC block encryption algorithms to protect plain text when used
with XML Encryption. Other mitigations should be considered when using
CBC block encryption, such as conveying the encrypted data over a secure
channel such as TLS. The CBC block encryption algorithms that are listed as
required remain so for backward compatibility.

  - https://www.w3.org/TR/xmlenc-core1/#bib-XMLENC-CBC-ATTACK
  - https://www.w3.org/TR/xmlenc-core1/#bib-XMLENC-CBC-ATTACK-COUNTERMEASURES
*/
const (
	BlockEncryptTripleDes = NamespaceXEnc + "tripledes-cbc"
	BlockEncryptAes128CBC = NamespaceXEnc + "aes128-cbc"
	BlockEncryptAes192CBC = NamespaceXEnc + "aes192-cbc"
	BlockEncryptAes256CBC = NamespaceXEnc + "aes256-cbc"
	BlockEncryptAes128GCM = NamespaceXEnc11 + "aes128-gcm"
	BlockEncryptAes192GCM = NamespaceXEnc11 + "aes192-gcm"
	BlockEncryptAes256GCM = NamespaceXEnc11 + "aes256-gcm"
)

// Stream Encryption
const (
	StreamEncryptConcatKDF = NamespaceXEnc11 + "ConcatKDF"
	StreamEncryptPBKDF2    = NamespaceXEnc11 + "pbkdf2"
)

const (
	KeyTransportRsa1_5    = NamespaceXEnc + "rsa-1_5" // Implementation of RSA v1.5 is NOT RECOMMENDED due to security risks associated with the algorithm.
	KeyTransportOaep      = NamespaceXEnc11 + "rsa-oaep"
	KeyTransportOaepMgf1p = NamespaceXEnc + "rsa-oaep-mgf1p"
)

// Key Agreement
const (
	KeyAgreementECDH_ES = NamespaceXEnc11 + "ECDH-ES"
	KeyAgreementDH      = NamespaceXEnc11 + "dh"
	KeyAgreementDH_ES   = NamespaceXEnc11 + "dh-es"
)

// Symmetric Key Wrap
const (
	KeyWrapTripleDes = NamespaceXEnc + "kw-tripledes"
	KeyWrapAes128    = NamespaceXEnc + "kw-aes128"
	KeyWrapAes192    = NamespaceXEnc + "kw-aes192"
	KeyWrapAes256    = NamespaceXEnc + "kw-aes256"
)

// Message Digest
const (
	MessageDigestSha1      = NamespaceDSig + "sha1"
	MessageDigestSha256    = NamespaceXEnc + "sha256"
	MessageDigestSha384    = NamespaceXEnc + "sha384"
	MessageDigestSha512    = NamespaceXEnc + "sha512"
	MessageDigestRipeMd160 = NamespaceXEnc + "ripemd160"
)

const EncodingBase64 = NamespaceDSig + "base64"

const (
	SignatureMethodRsaSha1     = NamespaceDSig + "rsa-sha1"
	SignatureMethodRsaSha256   = NamespaceDSigMore + "rsa-sha256"
	SignatureMethodRsaSha384   = NamespaceDSigMore + "rsa-sha384"
	SignatureMethodRsaSha512   = NamespaceDSigMore + "rsa-sha512"
	SignatureMethodEcdsaSha1   = NamespaceDSigMore + "ecdsa-sha1"
	SignatureMethodEcdsaSha256 = NamespaceDSigMore + "ecdsa-sha256"
	SignatureMethodEcdsaSha384 = NamespaceDSigMore + "ecdsa-sha384"
	SignatureMethodEcdsaSha512 = NamespaceDSigMore + "ecdsa-sha512"
)

// Well-known signature algorithms
const AlgorithmEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

var x509SignatureAlgorithmByIdentifier = map[string]x509.SignatureAlgorithm{
	SignatureMethodRsaSha1:     x509.SHA1WithRSA,
	SignatureMethodRsaSha256:   x509.SHA256WithRSA,
	SignatureMethodRsaSha384:   x509.SHA384WithRSA,
	SignatureMethodRsaSha512:   x509.SHA512WithRSA,
	SignatureMethodEcdsaSha1:   x509.ECDSAWithSHA1,
	SignatureMethodEcdsaSha256: x509.ECDSAWithSHA256,
	SignatureMethodEcdsaSha384: x509.ECDSAWithSHA384,
	SignatureMethodEcdsaSha512: x509.ECDSAWithSHA512,
}

type signatureMethodInfo struct {
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Hash               crypto.Hash
}

var signatureMethodsByIdentifier = map[string]signatureMethodInfo{}

func init() {
	for algo, hashToMethod := range signatureMethodIdentifiers {
		for hash, method := range hashToMethod {
			signatureMethodsByIdentifier[method] = signatureMethodInfo{
				PublicKeyAlgorithm: algo,
				Hash:               hash,
			}
		}
	}
}

var signatureMethodIdentifiers = map[x509.PublicKeyAlgorithm]map[crypto.Hash]string{
	x509.RSA: {
		crypto.SHA1:   SignatureMethodRsaSha1,
		crypto.SHA256: SignatureMethodRsaSha256,
		crypto.SHA384: SignatureMethodRsaSha384,
		crypto.SHA512: SignatureMethodRsaSha512,
	},
	x509.ECDSA: {
		crypto.SHA1:   SignatureMethodEcdsaSha1,
		crypto.SHA256: SignatureMethodEcdsaSha256,
		crypto.SHA384: SignatureMethodEcdsaSha384,
		crypto.SHA512: SignatureMethodEcdsaSha512,
	},
}
