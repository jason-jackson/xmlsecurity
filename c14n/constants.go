package c14n

// Canonicalization algorithms
type CanonicalizationAlgorithm string

const (
	C14nInclusive             CanonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	C14nInclusiveWithComments CanonicalizationAlgorithm = C14nInclusive + withComments
	C14nExclusive             CanonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n"
	C14nExclusiveWithComments CanonicalizationAlgorithm = C14nExclusive + withComments
	C14n11                    CanonicalizationAlgorithm = "http://www.w3.org/2006/12/xml-c14n11"
	C14n11WithComments        CanonicalizationAlgorithm = C14n11 + withComments
)

// helper constants
const (
	AttrXmlNamespace = "xmlns"
	AttrXml          = "xml"
	NamespaceXml     = "http://www.w3.org/XML/1998/namespace"

	withComments     = "#WithComments"
	defaultNamespace = ""
)
