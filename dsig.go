package xmlsecurity

import (
	"encoding/xml"

	"github.com/jason-jackson/xmlsecurity/c14n"
)

type (
	Transform struct {
		XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
		Algorithm string   `xml:",attr"`

		InclusiveNamespaces *InclusiveNamespaces `xml:",omitempty"`
		XPath               string               `xml:",omitempty"`
		Children            []Node               `xml:",any,omitempty"`
	}

	Transforms struct {
		XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
		Transforms []Transform `xml:"Transform"`
	}

	DigestMethod struct {
		XMLName   xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
		Algorithm DigestAlgorithm `xml:",attr"`

		Children []Node `xml:",any,omitempty"`
	}

	Reference struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
		Id      string   `xml:",attr,omitempty"`
		URI     string   `xml:",attr,omitempty"`
		Type    string   `xml:",attr,omitempty"`

		Transforms   *Transforms `xml:",omitempty"`
		DigestValue  string
		DigestMethod DigestMethod
	}

	CanonicalizationMethod struct {
		XMLName   xml.Name                       `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
		Algorithm c14n.CanonicalizationAlgorithm `xml:",attr"`

		Children []Node `xml:",any,omitempty"`
	}

	SignatureMethod struct {
		XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
		Algorithm string   `xml:",attr"`

		HMACOutputLength int
		Children         []Node `xml:",any,omitempty"`
	}

	SignedInfo struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
		Id      string   `xml:",attr"`

		CanonicalizationMethod CanonicalizationMethod
		SignatureMethod        SignatureMethod
		References             []Reference `xml:"Reference"`
	}

	SignatureValue struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
		Id      string   `xml:",attr"`
		Data    string   `xml:",chardata"`
	}

	KeyInfo struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
		Id      string   `xml:",attr"`

		KeyName            string
		KeyValue           KeyValue
		RetrievalMethod    RetrievalMethod
		X509Data           *X509Data           `xml:",omitempty"`
		PGPData            [][]byte            `xml:"PGPData>X509Certificate,omitempty"`  // TODO
		SPKIData           [][]byte            `xml:"SPKIData>X509Certificate,omitempty"` // TODO
		MgmtData           [][]byte            `xml:"MgmtData>X509Certificate,omitempty"` // TODO
		DEREncodedKeyValue *DEREncodedKeyValue `xml:",omitempty"`
		KeyInfoReference   *KeyInfoReference   `xml:",omitempty"`
		EncryptedKey       *EncryptedKey       `xml:",omitempty"`
		DerivedKey         *DerivedKey         `xml:",omitempty"` // Erroneously referred to as "Agreement" in dsig spec
		Children           []Node              `xml:",any,omitempty"`
	}

	KeyValue struct {
		XMLName     xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
		DSAKeyValue *DSAKeyValue `xml:",omitempty"`
		RSAKeyValue *RSAKeyValue `xml:",omitempty"`
		ECKeyValue  *ECKeyValue  `xml:",omitempty"`
		Children    []Node       `xml:",any,omitempty"`
	}

	DSAKeyValue struct {
		XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DSAKeyValue"`
		P           string   `xml:",omitempty"`
		Q           string   `xml:",omitempty"`
		G           string   `xml:",omitempty"`
		Y           string
		J           string `xml:",omitempty"`
		Seed        string `xml:",omitempty"`
		PgenCounter string `xml:",omitempty"`
	}

	RSAKeyValue struct {
		XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# RSAKeyValue"`
		Modulus  string   `xml:",omitempty"`
		Exponent string   `xml:",omitempty"`
	}

	X509Data struct {
		XMLName          xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
		X509Certificates [][]byte          `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
		X509IssuerSerial *X509IssuerSerial `xml:",omitempty"` // Deprecated
		X509SubjectName  string            `xml:",omitempty"`
		X509SKI          string            `xml:",omitempty"`
		X509Digest       string            `xml:",omitempty"` // TODO dsig11
	}

	// Deprecated
	X509IssuerSerial struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509IssuerSerial"`

		X509IssuerName   string
		X509SerialNumber string
	}

	Object struct {
		XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Object"`
		Id       string   `xml:",attr"`
		MimeType string   `xml:",attr"`
		Encoding string   `xml:",attr"`

		Children []Node `xml:",any,omitempty"`
	}

	Signature struct {
		XMLName    xml.Name   `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
		Id         string     `xml:",attr"`
		Attributes []xml.Attr `xml:",any,attr,omitempty"`

		SignedInfo     SignedInfo
		SignatureValue SignatureValue
		KeyInfo        *KeyInfo `xml:",omitempty"`
		Objects        []Object `xml:"Object,omitempty"`
	}

	// The KeyInfoReference element is preferred over use of
	// RetrievalMethod as it avoids use of Transform child elements
	// that introduce security risk and implementation challenges.
	RetrievalMethod struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# RetrievalMethod"`
		URI     string   `xml:",attr"`
		Type    string   `xml:",attr,omitempty"`

		Transforms *Transforms `xml:",omitempty"`
	}

	signatureParent struct {
		XMLName    xml.Name   `xml:"*"`
		Attributes []xml.Attr `xml:",any,attr,omitempty"`
		Signature  *Signature `xml:"Signature"`
		IdAttr     string     `xml:"-"`
	}

	InclusiveNamespaces struct {
		XMLName    xml.Name `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces"`
		PrefixList string   `xml:",attr"`
	}
)

func (p *signatureParent) RemoveSignature() error {
	p.Signature = nil
	return nil
}

func (p *signatureParent) GetId() string {
	id := "Id"
	if p.IdAttr != "" {
		id = p.IdAttr
	}

	for _, attr := range p.Attributes {
		if attr.Name.Local == id {
			return attr.Value
		}
	}

	return ""
}
