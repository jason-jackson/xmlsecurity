package xmlsecurity

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

type EncryptedType struct {
	Id       string  `xml:",attr,omitempty"`
	Type     *string `xml:",attr,omitempty"`
	MimeType string  `xml:",attr,omitempty"`
	Encoding *string `xml:",attr,omitempty"`

	EncryptionMethod     *EncryptionMethod `xml:",omitempty"`
	KeyInfo              *KeyInfo          `xml:",omitempty"`
	CipherData           CipherData
	EncryptionProperties *EncryptionProperties `xml:",omitempty"`
}

// EncryptionMethod specifies the type of encryption that was used.
type EncryptionMethod struct {
	Algorithm string `xml:",attr,omitempty"`

	KeySize    *int    `xml:",omitempty"`
	OAEPparams *string `xml:",omitempty"` // type="base64Binary"
	// Digest method is present for algorithms like RSA-OAEP.
	// See https://www.w3.org/TR/xmlenc-core1/.
	// To convey the digest methods an entity supports,
	// DigestMethod in extensions element is used.
	// See http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport.html.
	DigestMethod *DigestMethod `xml:",omitempty"`

	Children []Node `xml:",any,omitempty"`
}

type CipherData struct {
	CipherValue     *string          `xml:",omitempty"` // type="base64Binary"
	CipherReference *CipherReference `xml:",omitempty"`
}

func (c CipherData) GetValue() ([]byte, error) {
	if c.CipherValue != nil {
		return base64.StdEncoding.DecodeString(*c.CipherValue)
	}

	// TODO handle CipherReference
	return nil, fmt.Errorf("not implemented")
}

type CipherReference struct {
	URI        string      `xml:",attr"`
	Transforms []Transform `xml:"Transforms>Transform,omitempty"`
}

type EncryptedData struct {
	EncryptedType
}

type EncryptedKey struct {
	ReferenceList  ReferenceList `xml:",omitempty"`
	CarriedKeyName string        `xml:",omitempty"`
	Recipient      string        `xml:",omitempty"`
	EncryptedType
}

// xenc11
type DerivedKey struct {
	Recipient string  `xml:",attr,omitempty"`
	Id        string  `xml:",attr,omitempty"`
	Type      *string `xml:",attr,omitempty"`

	KeyDerivationMethod *KeyDerivationMethod `xml:",omitempty"` // xenc11
	ReferenceList       *ReferenceList       `xml:",omitempty"`
	DerivedKeyName      string               `xml:",omitempty"`
	MasterKeyName       string               `xml:",omitempty"`
}

type KeyDerivationMethod struct {
	Algorithm string `xml:",attr"`

	Children []Node `xml:",any,omitempty"`
}

type ReferenceList struct {
	DataReferences []ReferenceType `xml:"DataReference"`
	KeyReferences  []ReferenceType `xml:"KeyReference"`
}

type ReferenceType struct {
	URI string `xml:",attr"`

	Children []Node `xml:",any,omitempty"`
}

type EncryptionProperties struct {
	Id string `xml:",attr,omitempty"`

	EncryptionProperties []EncryptionProperty `xml:"EncryptionProperty,omitempty"`
}

type EncryptionProperty struct {
	Target     *string    `xml:",attr,omitempty"`
	Id         string     `xml:",attr,omitempty"`
	Attributes []xml.Attr `xml:",any,attr,omitempty"` // TODO only take from namespace="http://www.w3.org/XML/1998/namespace"

	Children []Node `xml:",any,omitempty"`
}

type EncryptedElement struct {
	EncryptedData []EncryptedData `xml:"xenc:EncryptedData"`
	EncryptedKeys []EncryptedKey  `xml:"xenc:EncryptedKey"`
}
