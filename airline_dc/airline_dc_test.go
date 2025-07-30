package airline_dc

import (
	"testing"
)

const airShoppingXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<IATA_AirShoppingRQ xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:ns2="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xmlns:ns3="http://www.w3.org/2000/09/xmldsig#">
	<DistributionChain>
		<ns2:DistributionChainLink>
			<ns2:Ordinal>1</ns2:Ordinal>
			<ns2:OrgRole>Seller</ns2:OrgRole>
			<ns2:ParticipatingOrg>
				<ns2:OrgID>org1</ns2:OrgID>
			</ns2:ParticipatingOrg>
			<ns2:SalesBranch>
				<ns2:SalesBranchID>NDC</ns2:SalesBranchID>
			</ns2:SalesBranch>
		</ns2:DistributionChainLink>
		<ns2:DistributionChainLink>
			<ns2:Ordinal>2</ns2:Ordinal>
			<ns2:OrgRole>Distributor</ns2:OrgRole>
			<ns2:ParticipatingOrg>
				<ns2:OrgID>org1</ns2:OrgID>
			</ns2:ParticipatingOrg>
		</ns2:DistributionChainLink>
		<ns2:DistributionChainLink>
			<ns2:Ordinal>3</ns2:Ordinal>
			<ns2:OrgRole>Carrier</ns2:OrgRole>
			<ns2:ParticipatingOrg>
				<ns2:OrgID>EX</ns2:OrgID>
			</ns2:ParticipatingOrg>
		</ns2:DistributionChainLink>
	</DistributionChain>
	<POS>
		<ns2:Country>
			<ns2:CountryCode>EX</ns2:CountryCode>
		</ns2:Country>
	</POS>
	<Request>
		<ns2:FlightRequest>
			<ns2:FlightRequestOriginDestinationsCriteria>
				<ns2:OriginDestCriteria>
					<ns2:DestArrivalCriteria>
						<ns2:IATA_LocationCode>EXB</ns2:IATA_LocationCode>
					</ns2:DestArrivalCriteria>
					<ns2:OriginDepCriteria>
						<ns2:Date>2025-08-05</ns2:Date>
						<ns2:IATA_LocationCode>EXA</ns2:IATA_LocationCode>
					</ns2:OriginDepCriteria>
					<ns2:OriginDestID>OD1</ns2:OriginDestID>
				</ns2:OriginDestCriteria>
				<ns2:OriginDestCriteria>
					<ns2:DestArrivalCriteria>
						<ns2:IATA_LocationCode>EXA</ns2:IATA_LocationCode>
					</ns2:DestArrivalCriteria>
					<ns2:OriginDepCriteria>
						<ns2:Date>2025-08-23</ns2:Date>
						<ns2:IATA_LocationCode>EXB</ns2:IATA_LocationCode>
					</ns2:OriginDepCriteria>
					<ns2:OriginDestID>OD2</ns2:OriginDestID>
				</ns2:OriginDestCriteria>
			</ns2:FlightRequestOriginDestinationsCriteria>
		</ns2:FlightRequest>
		<ns2:PaxList>
			<ns2:Pax>
				<ns2:PaxID>PAX1</ns2:PaxID>
				<ns2:PTC>ADT</ns2:PTC>
			</ns2:Pax>
		</ns2:PaxList>
	</Request>
</IATA_AirShoppingRQ>`

const sellerDistributorCarrierXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:IATA_AirShoppingRQ xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xmlns:ns2="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:ns3="http://www.w3.org/2000/09/xmldsig#">
	<ns2:DistributionChain>
		<DistributionChainLink>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
			<SalesBranch>
				<SalesBranchID>NDC</SalesBranchID>
			</SalesBranch>
		</DistributionChainLink>
		<DistributionChainLink>
			<Ordinal>2</Ordinal>
			<OrgRole>Distributor</OrgRole>
			<ParticipatingOrg>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
		</DistributionChainLink>
		<DistributionChainLink>
			<Ordinal>3</Ordinal>
			<OrgRole>Carrier</OrgRole>
			<ParticipatingOrg>
				<OrgID>org3</OrgID>
			</ParticipatingOrg>
		</DistributionChainLink>
	</ns2:DistributionChain>
	<ns2:POS>
		<Country>
			<CountryCode>EX</CountryCode>
		</Country>
	</ns2:POS>
	<ns2:Request>
		<FlightRequest>
			<FlightRequestOriginDestinationsCriteria>
				<OriginDestCriteria>
					<DestArrivalCriteria>
						<IATA_LocationCode>EXC</IATA_LocationCode>
					</DestArrivalCriteria>
					<OriginDepCriteria>
						<Date>2025-07-16</Date>
						<IATA_LocationCode>EXA</IATA_LocationCode>
					</OriginDepCriteria>
					<OriginDestID>OD1</OriginDestID>
				</OriginDestCriteria>
			</FlightRequestOriginDestinationsCriteria>
		</FlightRequest>
		<PaxList>
			<Pax>
				<PaxID>PAX1</PaxID>
				<PTC>ADT</PTC>
			</Pax>
		</PaxList>
	</ns2:Request>
</ns2:IATA_AirShoppingRQ>`

const ns2PrefixedXml = `<DistributionChain>
	<ns2:DistributionChainLink>
		<ns2:Ordinal>1</ns2:Ordinal>
		<ns2:OrgRole>Seller</ns2:OrgRole>
		<ns2:ParticipatingOrg>
			<ns2:OrgID>org1</ns2:OrgID>
		</ns2:ParticipatingOrg>
		<ns2:SalesAgent>
			<ns2:SalesAgentID>EXAMPLE</ns2:SalesAgentID>
		</ns2:SalesAgent>
		<ns2:SalesBranch>
			<ns2:SalesBranchID>NDC</ns2:SalesBranchID>
		</ns2:SalesBranch>
	</ns2:DistributionChainLink>
</DistributionChain>`

const easdPrefixedXml = `
<easd:DistributionChain>
	<DistributionChainLink>
		<Ordinal>1</Ordinal>
		<OrgRole>Carrier</OrgRole>
		<ParticipatingOrg>
			<OrgID>carrier1</OrgID>
		</ParticipatingOrg>
	</DistributionChainLink>
</easd:DistributionChain>`

const singleCarrierXml = `<easd:DistributionChain>
	<DistributionChainLink>
		<Ordinal>1</Ordinal>
		<OrgRole>Carrier</OrgRole>
		<ParticipatingOrg>
			<OrgID>IKUK99999999DC01</OrgID>
		</ParticipatingOrg>
		<Pos>
			<Country>
				<CountryCode>EX</CountryCode>
			</Country>
		</Pos>
		</DistributionChainLink>
</easd:DistributionChain>`

const sellerWithAgentBranchAndAgentIdXml = `<?xml version="1.0" encoding="UTF-8"?>
<easd:IATA_OrderSalesInfoAccountingDocNotifRQ xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xs="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:easd="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:cns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xsi:schemaLocation="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes  IATA_OrderSalesInfoAccountingDocNotifRQ.xsd"
	xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes">
	<easd:DistributionChain>
		<DistributionChainLink>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<Name>Example Airlines</Name>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
			<SalesAgent>
				<SalesAgentID>12341011</SalesAgentID>
			</SalesAgent>
			<SalesBranch>
				<SalesBranchID>EXWEBDW</SalesBranchID>
			</SalesBranch>
			<Pos></Pos>
		</DistributionChainLink>
		</easd:DistributionChain>
</easd:IATA_OrderSalesInfoAccountingDocNotifRQ>`

const sellerAndCarrierWithPosSalesAgentIdXml = `<?xml version="1.0" encoding="UTF-8"?>
<easd:IATA_OrderSalesInfoAccountingDocNotifRQ xmlns:cns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xsi:schemaLocation="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes  IATA_OrderSalesInfoAccountingDocNotifRQ.xsd"
	xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xs="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:easd="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage">
	<easd:DistributionChain>
		<DistributionChainLink>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<n>TCS-EX</n>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
			<SalesAgent>
				<SalesAgentID>LT_173</SalesAgentID>
			</SalesAgent>
			<Pos>
				<City>
					<CityName>EXA</CityName>
				</City>
				<Country>
					<CountryCode>EX</CountryCode>
				</Country>
			</Pos>
		</DistributionChainLink>
		<DistributionChainLink>
			<Ordinal>2</Ordinal>
			<OrgRole>CARRIER</OrgRole>
			<ParticipatingOrg>
				<n>Example Air</n>
				<OrgID>EX</OrgID>
			</ParticipatingOrg>
			<Pos>
				<City>
					<CityName>EXA</CityName>
				</City>
				<Country>
					<CountryCode>EX</CountryCode>
				</Country>
			</Pos>
		</DistributionChainLink>
	</easd:DistributionChain>
</easd:IATA_OrderSalesInfoAccountingDocNotifRQ>`

const sellerAndDistributorXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:IATA_AirShoppingRQ xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xmlns:ns2="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:ns3="http://www.w3.org/2000/09/xmldsig#">
	<ns2:DistributionChain>
		<DistributionChainLink>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
			<SalesBranch>
				<SalesBranchID>NDC</SalesBranchID>
			</SalesBranch>
		</DistributionChainLink>
		<DistributionChainLink>
			<Ordinal>2</Ordinal>
			<OrgRole>Distributor</OrgRole>
			<ParticipatingOrg>
				<OrgID>org1</OrgID>
			</ParticipatingOrg>
		</DistributionChainLink>
		<DistributionChainLink>
			<Ordinal>3</Ordinal>
			<OrgRole>Carrier</OrgRole>
			<ParticipatingOrg>
				<OrgID>org3</OrgID>
			</ParticipatingOrg>
		</DistributionChainLink>
	</ns2:DistributionChain>
	<ns2:POS>
		<Country>
			<CountryCode>EX</CountryCode>
		</Country>
	</ns2:POS>
	<ns2:Request>
		<FlightRequest>
			<FlightRequestOriginDestinationsCriteria>
				<OriginDestCriteria>
					<DestArrivalCriteria>
						<IATA_LocationCode>EXA</IATA_LocationCode>
					</DestArrivalCriteria>
					<OriginDepCriteria>
						<Date>2025-07-16</Date>
						<IATA_LocationCode>EXB</IATA_LocationCode>
					</OriginDepCriteria>
					<OriginDestID>OD1</OriginDestID>
				</OriginDestCriteria>
			</FlightRequestOriginDestinationsCriteria>
		</FlightRequest>
		<PaxList>
			<Pax>
				<PaxID>PAX1</PaxID>
				<PTC>ADT</PTC>
			</Pax>
		</PaxList>
	</ns2:Request>
</ns2:IATA_AirShoppingRQ>`

const fullDistributionChainModelXml = `<?xml version="1.0" encoding="UTF-8"?>
<easd:IATA_OrderSalesInfoAccountingDocNotifRQ xmlns:cns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xsi:schemaLocation="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes  IATA_OrderSalesInfoAccountingDocNotifRQ.xsd"
	xmlns="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersCommonTypes"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xs="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage"
	xmlns:easd="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage">
	<easd:DistributionChain>
		<DistributionChainLink>
			<ContactInfo>
				<ContactInfoID>CONTACT_001</ContactInfoID>
				<ContactPurposeText>Business</ContactPurposeText>
				<ContactPurposeText>Emergency</ContactPurposeText>
				<ContactRefusedInd>false</ContactRefusedInd>
				<EmailAddress>
					<ContactTypeText>Business</ContactTypeText>
					<EmailAddressText>agent@exampleairlines.com</EmailAddressText>
				</EmailAddress>
				<EmailAddress>
					<ContactTypeText>Personal</ContactTypeText>
					<EmailAddressText>personal@example.com</EmailAddressText>
				</EmailAddress>
				<Individual>
					<AddlName>
						<Name>Middle</Name>
						<NameTypeCode>MIDDLE</NameTypeCode>
					</AddlName>
					<Birthdate>1990-05-15</Birthdate>
					<BirthplaceText>Example City, Country</BirthplaceText>
					<GenderCode>M</GenderCode>
					<GivenName>John</GivenName>
					<GivenName>James</GivenName>
					<IndividualID>IND_12345</IndividualID>
					<MiddleName>Middle</MiddleName>
					<SuffixName>Jr</SuffixName>
					<Surname>Smith</Surname>
					<TitleName>Mr</TitleName>
				</Individual>
				<IndividualRefID>REF_IND_001</IndividualRefID>
				<OtherAddress>
					<ContactTypeText>Work</ContactTypeText>
					<OtherAddressText>Building 123, Floor 5, Office 501</OtherAddressText>
				</OtherAddress>
				<PaxSegmentRefID>PAX_SEG_001</PaxSegmentRefID>
				<Phone>
					<AreaCodeNumber>11</AreaCodeNumber>
					<ContactTypeText>Mobile</ContactTypeText>
					<CountryDialingCode>1</CountryDialingCode>
					<ExtensionNumber>1234</ExtensionNumber>
					<PhoneNumber>5551234567</PhoneNumber>
				</Phone>
				<Phone>
					<AreaCodeNumber>11</AreaCodeNumber>
					<ContactTypeText>Work</ContactTypeText>
					<CountryDialingCode>1</CountryDialingCode>
					<PhoneNumber>4441234567</PhoneNumber>
				</Phone>
				<PostalAddress>
					<BuildingRoomText>Suite 100</BuildingRoomText>
					<CityName>Example City</CityName>
					<ContactTypeText>Business</ContactTypeText>
					<CountryCode>EX</CountryCode>
					<CountryName>Example Country</CountryName>
					<CountrySubDivisionName>Example Province</CountrySubDivisionName>
					<POBoxCode>12345</POBoxCode>
					<PostalCode>11564</PostalCode>
					<StreetText>Main Street</StreetText>
					<StreetText>Near Business Center</StreetText>
				</PostalAddress>
				<RelationshipToPax>Agent</RelationshipToPax>
			</ContactInfo>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<Name>Example Air Sales</Name>
				<OrgID>EX_SALES_001</OrgID>
			</ParticipatingOrg>
			<SalesAgent>
				<SalesAgentID>AGENT_EX_001</SalesAgentID>
			</SalesAgent>
			<SalesBranch>
				<SalesBranchID>EX_BRANCH_EXP</SalesBranchID>
			</SalesBranch>
			<VerifiablePresentation>eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...</VerifiablePresentation>
		</DistributionChainLink>
	</easd:DistributionChain>
</easd:IATA_OrderSalesInfoAccountingDocNotifRQ>`

const minimalContactInfoXml = `<?xml version="1.0" encoding="UTF-8"?>
<easd:IATA_OrderSalesInfoAccountingDocNotifRQ xmlns:easd="http://www.iata.org/IATA/2015/EASD/00/IATA_OffersAndOrdersMessage">
	<easd:DistributionChain>
		<DistributionChainLink>
			<ContactInfo>
				<ContactInfoID>MIN_CONTACT_001</ContactInfoID>
				<EmailAddress>
					<EmailAddressText>minimal@example.com</EmailAddressText>
				</EmailAddress>
			</ContactInfo>
			<Ordinal>1</Ordinal>
			<OrgRole>Seller</OrgRole>
			<ParticipatingOrg>
				<Name>Minimal Org</Name>
				<OrgID>MIN_ORG_001</OrgID>
			</ParticipatingOrg>
		</DistributionChainLink>
	</easd:DistributionChain>
</easd:IATA_OrderSalesInfoAccountingDocNotifRQ>`

func validateDistributionChainLink(t *testing.T, dc DistributionChainLink, expectedOrgId string, expectedOrdinal int, expectedSalesBranchId string, expectedOrgRole string) {
	if dc.ParticipatingOrg == nil || dc.ParticipatingOrg.OrgID != expectedOrgId {
		t.Errorf("Expected ParticipatingOrg OrgID %s, got %s", expectedOrgId, dc.ParticipatingOrg.OrgID)
	}

	if dc.Ordinal != expectedOrdinal {
		t.Errorf("Expected Ordinal %d, got %d", expectedOrdinal, dc.Ordinal)
	}

	if expectedSalesBranchId != "" && (dc.SalesBranch == nil || dc.SalesBranch.SalesBranchID != expectedSalesBranchId) {
		t.Errorf("Expected SalesBranchID %s", expectedSalesBranchId)
	}

	if expectedOrgRole != "" && dc.OrgRole != expectedOrgRole {
		t.Errorf("Expected OrgRole %s, got %s", expectedOrgRole, dc.OrgRole)
	}
}

func extractDcNode(t *testing.T, inputXml string) DistributionChain {
	dc, err := getDcNode(inputXml)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if err != nil {
		t.Fatalf("Expected no error unmarshaling DistributionChain, got %v", err)
	}

	return dc
}

func TestAirShoppingDc(t *testing.T) {
	dc := extractDcNode(t, airShoppingXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "org1", 1, "NDC", "Seller")
	validateDistributionChainLink(t, dc.DistributionChainLink[1], "org1", 2, "", "Distributor")
	validateDistributionChainLink(t, dc.DistributionChainLink[2], "EX", 3, "", "Carrier")
}

func TestSellerDistributorCarrierDc(t *testing.T) {
	dc := extractDcNode(t, sellerDistributorCarrierXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "org1", 1, "NDC", "Seller")
	validateDistributionChainLink(t, dc.DistributionChainLink[1], "org1", 2, "", "Distributor")
	validateDistributionChainLink(t, dc.DistributionChainLink[2], "org3", 3, "", "Carrier")
}

func TestSingleCarrierDc(t *testing.T) {
	dc := extractDcNode(t, singleCarrierXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "IKUK99999999DC01", 1, "", "Carrier")
}

func TestSellerWithAgentBranchAndAgentIdDc(t *testing.T) {
	dc := extractDcNode(t, sellerWithAgentBranchAndAgentIdXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "org1", 1, "EXWEBDW", "Seller")
	if dc.DistributionChainLink[0].SalesAgent == nil || dc.DistributionChainLink[0].SalesAgent.SalesAgentID != "12341011" {
		t.Errorf("Expected SalesAgentID 12341011, got %s", dc.DistributionChainLink[0].SalesAgent)
	}
	if dc.DistributionChainLink[0].ParticipatingOrg.Name != "Example Airlines" {
		t.Errorf("Expected ParticipatingOrg Name Example Airlines, got %s", dc.DistributionChainLink[0].ParticipatingOrg.Name)
	}
}

func TestSellerAndCarrierWithPosSalesAgentIdDc(t *testing.T) {
	dc := extractDcNode(t, sellerAndCarrierWithPosSalesAgentIdXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "org1", 1, "", "Seller")
	if dc.DistributionChainLink[0].SalesAgent == nil || dc.DistributionChainLink[0].SalesAgent.SalesAgentID != "LT_173" {
		t.Errorf("Expected SalesAgentID LT_173, got %+v", dc.DistributionChainLink[0].SalesAgent)
	}
}

func TestSellerAndDistributorDc(t *testing.T) {
	dc := extractDcNode(t, sellerAndDistributorXml)

	validateDistributionChainLink(t, dc.DistributionChainLink[0], "org1", 1, "NDC", "Seller")
	validateDistributionChainLink(t, dc.DistributionChainLink[1], "org1", 2, "", "Distributor")
	validateDistributionChainLink(t, dc.DistributionChainLink[2], "org3", 3, "", "Carrier")
}

func TestFullDistributionChainModel(t *testing.T) {
	dc := extractDcNode(t, fullDistributionChainModelXml)

	// Validate that we have exactly one distribution chain link
	if len(dc.DistributionChainLink) != 1 {
		t.Errorf("Expected 1 distribution chain link, got %d", len(dc.DistributionChainLink))
	}

	// Validate the single distribution chain link with all fields populated
	link := dc.DistributionChainLink[0]
	validateDistributionChainLink(t, link, "EX_SALES_001", 1, "EX_BRANCH_EXP", "Seller")

	// Validate SalesAgent
	if link.SalesAgent == nil || link.SalesAgent.SalesAgentID != "AGENT_EX_001" {
		t.Errorf("Expected SalesAgentID AGENT_EX_001, got %+v", link.SalesAgent)
	}

	// Validate ParticipatingOrg Name
	if link.ParticipatingOrg.Name != "Example Air Sales" {
		t.Errorf("Expected ParticipatingOrg Name 'Example Air Sales', got %s", link.ParticipatingOrg.Name)
	}

	// Validate VerifiablePresentation
	if link.VerifiablePresentation != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." {
		t.Errorf("Expected VerifiablePresentation to be set, got %s", link.VerifiablePresentation)
	}

	// Validate ContactInfo
	if link.ContactInfo == nil {
		t.Fatal("Expected ContactInfo to be set")
	}

	contactInfo := link.ContactInfo
	if contactInfo.ContactInfoID != "CONTACT_001" {
		t.Errorf("Expected ContactInfoID CONTACT_001, got %s", contactInfo.ContactInfoID)
	}

	if len(contactInfo.ContactPurposeText) != 2 || contactInfo.ContactPurposeText[0] != "Business" || contactInfo.ContactPurposeText[1] != "Emergency" {
		t.Errorf("Expected ContactPurposeText [Business, Emergency], got %v", contactInfo.ContactPurposeText)
	}

	if contactInfo.ContactRefusedInd != false {
		t.Errorf("Expected ContactRefusedInd false, got %v", contactInfo.ContactRefusedInd)
	}

	// Validate EmailAddress
	if len(contactInfo.EmailAddress) != 2 {
		t.Errorf("Expected 2 email addresses, got %d", len(contactInfo.EmailAddress))
	}
	if contactInfo.EmailAddress[0].EmailAddressText != "agent@exampleairlines.com" {
		t.Errorf("Expected first email agent@exampleairlines.com, got %s", contactInfo.EmailAddress[0].EmailAddressText)
	}
	if contactInfo.EmailAddress[0].ContactTypeText != "Business" {
		t.Errorf("Expected first email contact type Business, got %s", contactInfo.EmailAddress[0].ContactTypeText)
	}
	if contactInfo.EmailAddress[1].EmailAddressText != "personal@example.com" {
		t.Errorf("Expected second email personal@example.com, got %s", contactInfo.EmailAddress[1].EmailAddressText)
	}

	// Validate Individual
	if contactInfo.Individual == nil {
		t.Fatal("Expected Individual to be set")
	}
	individual := contactInfo.Individual
	if individual.IndividualID != "IND_12345" {
		t.Errorf("Expected IndividualID IND_12345, got %s", individual.IndividualID)
	}
	if individual.Birthdate != "1990-05-15" {
		t.Errorf("Expected Birthdate 1990-05-15, got %s", individual.Birthdate)
	}
	if individual.BirthplaceText != "Example City, Country" {
		t.Errorf("Expected BirthplaceText 'Example City, Country', got %s", individual.BirthplaceText)
	}
	if individual.GenderCode != "M" {
		t.Errorf("Expected GenderCode M, got %s", individual.GenderCode)
	}
	if len(individual.GivenName) != 2 || individual.GivenName[0] != "John" || individual.GivenName[1] != "James" {
		t.Errorf("Expected GivenName [John, James], got %v", individual.GivenName)
	}
	if len(individual.MiddleName) != 1 || individual.MiddleName[0] != "Middle" {
		t.Errorf("Expected MiddleName [Middle], got %v", individual.MiddleName)
	}
	if individual.SuffixName != "Jr" {
		t.Errorf("Expected SuffixName Jr, got %s", individual.SuffixName)
	}
	if individual.Surname != "Smith" {
		t.Errorf("Expected Surname Smith, got %s", individual.Surname)
	}
	if individual.TitleName != "Mr" {
		t.Errorf("Expected TitleName Mr, got %s", individual.TitleName)
	}

	// Validate AddlName
	if len(individual.AddlName) != 1 {
		t.Errorf("Expected 1 additional name, got %d", len(individual.AddlName))
	}
	if individual.AddlName[0].Name != "Middle" || individual.AddlName[0].NameTypeCode != "MIDDLE" {
		t.Errorf("Expected AddlName {Middle, MIDDLE}, got %+v", individual.AddlName[0])
	}

	// Validate other ContactInfo fields
	if contactInfo.IndividualRefID != "REF_IND_001" {
		t.Errorf("Expected IndividualRefID REF_IND_001, got %s", contactInfo.IndividualRefID)
	}
	if contactInfo.PaxSegmentRefID != "PAX_SEG_001" {
		t.Errorf("Expected PaxSegmentRefID PAX_SEG_001, got %s", contactInfo.PaxSegmentRefID)
	}
	if contactInfo.RelationshipToPax != "Agent" {
		t.Errorf("Expected RelationshipToPax Agent, got %s", contactInfo.RelationshipToPax)
	}

	// Validate OtherAddress
	if len(contactInfo.OtherAddress) != 1 {
		t.Errorf("Expected 1 other address, got %d", len(contactInfo.OtherAddress))
	}
	if contactInfo.OtherAddress[0].ContactTypeText != "Work" || contactInfo.OtherAddress[0].OtherAddressText != "Building 123, Floor 5, Office 501" {
		t.Errorf("Expected OtherAddress {Work, Building 123, Floor 5, Office 501}, got %+v", contactInfo.OtherAddress[0])
	}

	// Validate Phone numbers
	if len(contactInfo.Phone) != 2 {
		t.Errorf("Expected 2 phone numbers, got %d", len(contactInfo.Phone))
	}
	phone1 := contactInfo.Phone[0]
	if phone1.PhoneNumber != "5551234567" || phone1.CountryDialingCode != "1" || phone1.AreaCodeNumber != "11" || phone1.ExtensionNumber != "1234" || phone1.ContactTypeText != "Mobile" {
		t.Errorf("Expected first phone {5551234567, 1, 11, 1234, Mobile}, got {%s, %s, %s, %s, %s}",
			phone1.PhoneNumber, phone1.CountryDialingCode, phone1.AreaCodeNumber, phone1.ExtensionNumber, phone1.ContactTypeText)
	}
	phone2 := contactInfo.Phone[1]
	if phone2.PhoneNumber != "4441234567" || phone2.CountryDialingCode != "1" || phone2.ContactTypeText != "Work" {
		t.Errorf("Expected second phone {4441234567, 1, Work}, got {%s, %s, %s}",
			phone2.PhoneNumber, phone2.CountryDialingCode, phone2.ContactTypeText)
	}

	// Validate PostalAddress
	if len(contactInfo.PostalAddress) != 1 {
		t.Errorf("Expected 1 postal address, got %d", len(contactInfo.PostalAddress))
	}
	postalAddr := contactInfo.PostalAddress[0]
	if postalAddr.CityName != "Example City" || postalAddr.CountryCode != "EX" || postalAddr.CountryName != "Example Country" {
		t.Errorf("Expected postal address {Example City, EX, Example Country}, got {%s, %s, %s}",
			postalAddr.CityName, postalAddr.CountryCode, postalAddr.CountryName)
	}
	if postalAddr.BuildingRoomText != "Suite 100" || postalAddr.POBoxCode != "12345" || postalAddr.PostalCode != "11564" {
		t.Errorf("Expected postal details {Suite 100, 12345, 11564}, got {%s, %s, %s}",
			postalAddr.BuildingRoomText, postalAddr.POBoxCode, postalAddr.PostalCode)
	}
	if len(postalAddr.StreetText) != 2 || postalAddr.StreetText[0] != "Main Street" || postalAddr.StreetText[1] != "Near Business Center" {
		t.Errorf("Expected StreetText [Main Street, Near Business Center], got %v", postalAddr.StreetText)
	}
}

func TestMinimalContactInfo(t *testing.T) {
	dc := extractDcNode(t, minimalContactInfoXml)

	// Validate basic structure
	if len(dc.DistributionChainLink) != 1 {
		t.Errorf("Expected 1 distribution chain link, got %d", len(dc.DistributionChainLink))
	}

	link := dc.DistributionChainLink[0]
	validateDistributionChainLink(t, link, "MIN_ORG_001", 1, "", "Seller")

	// Validate minimal ContactInfo
	if link.ContactInfo == nil {
		t.Fatal("Expected ContactInfo to be set")
	}

	contactInfo := link.ContactInfo
	if contactInfo.ContactInfoID != "MIN_CONTACT_001" {
		t.Errorf("Expected ContactInfoID MIN_CONTACT_001, got %s", contactInfo.ContactInfoID)
	}

	// Validate minimal EmailAddress
	if len(contactInfo.EmailAddress) != 1 {
		t.Errorf("Expected 1 email address, got %d", len(contactInfo.EmailAddress))
	}
	if contactInfo.EmailAddress[0].EmailAddressText != "minimal@example.com" {
		t.Errorf("Expected email minimal@example.com, got %s", contactInfo.EmailAddress[0].EmailAddressText)
	}

	// Ensure other fields are empty/nil
	if contactInfo.Individual != nil {
		t.Errorf("Expected Individual to be nil in minimal case, got %+v", contactInfo.Individual)
	}
	if len(contactInfo.Phone) != 0 {
		t.Errorf("Expected no phone numbers in minimal case, got %d", len(contactInfo.Phone))
	}
}

// Test with different XML namespace prefixes
func TestGetDcNode_NamespacePrefixes(t *testing.T) {
	namespaceCases := []struct {
		name     string
		inputXML string
	}{
		{
			name:     "ns2 prefix",
			inputXML: ns2PrefixedXml,
		},
		{
			name:     "easd prefix",
			inputXML: easdPrefixedXml,
		},
	}

	for _, tc := range namespaceCases {
		t.Run(tc.name, func(t *testing.T) {
			dc, err := getDcNode(tc.inputXML)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(dc.DistributionChainLink) == 0 {
				t.Errorf("Expected at least one chain link")
			}
		})
	}
}
