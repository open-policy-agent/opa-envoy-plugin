package airline_dc

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

func getDcNode(input_xml string) (DistributionChain, error) {
	if input_xml == "" {
		return DistributionChain{}, fmt.Errorf("input XML cannot be empty")
	}

	xml_reader := strings.NewReader(input_xml)
	decoder := xml.NewDecoder(xml_reader)

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if se.Name.Local == "DistributionChain" {
				var dc DistributionChain
				if err := decoder.DecodeElement(&dc, &se); err != nil {
					return DistributionChain{}, fmt.Errorf("failed to decode DistributionChain: %w", err)
				}
				return dc, nil
			}
		}
	}
	return DistributionChain{}, fmt.Errorf("DistributionChain not found in XML")
}

func ParseXmlDc(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {

	var input_xml string

	if err := ast.As(a.Value, &input_xml); err != nil {
		return nil, err
	}
	dc, err := getDcNode(input_xml)

	if err != nil {
		return nil, err
	}

	v, err := ast.InterfaceToValue(dc)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(v), nil
}
