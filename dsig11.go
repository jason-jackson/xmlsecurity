package xmlsecurity

import (
	"encoding/xml"
)

type (
	Curve struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# Curve"`
		A       string
		B       string
	}

	DEREncodedKeyValue struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# DEREncodedKeyValue"`
		Id      string   `xml:",attr,omitempty"`
		Data    string   `xml:",chardata"`
	}

	ECKeyValue struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# ECKeyValue"`
		Id      string   `xml:",attr,omitempty"`

		NamedCurve   *NamedCurve
		ECParameters *ECParameters
		PublicKey    string
	}

	ECParameters struct {
		XMLName        xml.Name `xml:"http://www.w3.org/2009/xmldsig11# NamedCurve"`
		FieldID        FieldID
		Curve          Curve           // TODO type="dsig11:CurveType"
		Base           string          // base64 encoded
		Order          string          // base64 encoded
		CoFactor       *int            `xml:",omitempty"`
		ValidationData *ValidationData `xml:",omitempty"`
	}

	FieldID struct {
		Prime    *Prime `xml:",omitempty"`
		TnB      *TnB   `xml:",omitempty"`
		PnB      *PnB   `xml:",omitempty"`
		GnB      *GnB   `xml:",omitempty"`
		Children []Node `xml:",any,omitempty"`
	}

	GnB struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# GnB"`
		M       uint
	}

	KeyInfoReference struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# KeyInfoReference"`
		URI     string   `xml:",attr"`
		Id      string   `xml:",attr,omitempty"`
	}

	NamedCurve struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# NamedCurve"`
		URI     string   `xml:",attr"`
	}

	PnB struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# PnB"`
		M       uint
		K1      uint
		K2      uint
		K3      uint
	}

	Prime struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# Prime"`
		P       string   // represents the field size in bits. It is encoded as a positiveInteger.
	}

	TnB struct {
		XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# TnB"`
		M       uint
		K       uint
	}

	ValidationData struct {
		XMLName       xml.Name `xml:"http://www.w3.org/2009/xmldsig11# ValidationData"`
		HashAlgorithm string   `xml:"hashAlgorithm,attr"`
		Seed          string
	}
)
