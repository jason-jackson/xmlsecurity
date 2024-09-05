package xmlsecurity

import "encoding/xml"

type Node struct {
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
	Children   []Node     `xml:",any,omitempty"`
	Value      string     `xml:",chardata"`
}
