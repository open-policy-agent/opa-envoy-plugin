package airline_dc

// Basic/Leaf structs - no dependencies
type AddlName struct {
	Name         string `json:"name,omitempty"`
	NameTypeCode string `json:"nameTypeCode,omitempty"`
}

type EmailAddress struct {
	ContactTypeText  string `json:"contactTypeText,omitempty"`
	EmailAddressText string `json:"emailAddressText,omitempty"`
}

type OtherAddress struct {
	ContactTypeText  string `json:"contactTypeText,omitempty"`
	OtherAddressText string `json:"otherAddressText,omitempty"`
}

type Phone struct {
	AreaCodeNumber     string `json:"areaCodeNumber,omitempty"`
	ContactTypeText    string `json:"contactTypeText,omitempty"`
	CountryDialingCode string `json:"countryDialingCode,omitempty"`
	ExtensionNumber    string `json:"extensionNumber,omitempty"`
	PhoneNumber        string `json:"phoneNumber,omitempty"`
}

type PostalAddress struct {
	BuildingRoomText       string   `json:"buildingRoomText,omitempty"`
	CityName               string   `json:"cityName,omitempty"`
	ContactTypeText        string   `json:"contactTypeText,omitempty"`
	CountryCode            string   `json:"countryCode,omitempty"`
	CountryName            string   `json:"countryName,omitempty"`
	CountrySubDivisionName string   `json:"countrySubDivisionName,omitempty"`
	POBoxCode              string   `json:"poboxCode,omitempty"`
	PostalCode             string   `json:"postalCode,omitempty"`
	StreetText             []string `json:"streetText,omitempty"`
}

type ParticipatingOrg struct {
	OrgID string `json:"orgID,omitempty"`
	Name  string `json:"name,omitempty"`
}

type SalesAgent struct {
	SalesAgentID string `json:"salesAgentID,omitempty"`
}

type SalesBranch struct {
	SalesBranchID string `json:"salesBranchID,omitempty"`
}

// Intermediate structs - depend on basic structs
type Individual struct {
	AddlName       []AddlName `json:"addlName,omitempty"`
	Birthdate      string     `json:"birthdate,omitempty"`
	BirthplaceText string     `json:"birthplaceText,omitempty"`
	GenderCode     string     `json:"genderCode,omitempty"`
	GivenName      []string   `json:"givenName,omitempty"`
	IndividualID   string     `json:"individualID,omitempty"`
	MiddleName     []string   `json:"middleName,omitempty"`
	SuffixName     string     `json:"suffixName,omitempty"`
	Surname        string     `json:"surname,omitempty"`
	TitleName      string     `json:"titleName,omitempty"`
}

type ContactInfo struct {
	ContactInfoID      string          `json:"contactInfoID,omitempty"`
	ContactPurposeText []string        `json:"contactPurposeText,omitempty"`
	ContactRefusedInd  bool            `json:"contactRefusedInd,omitempty"`
	EmailAddress       []EmailAddress  `json:"emailAddress,omitempty"`
	Individual         *Individual     `json:"individual,omitempty"`
	IndividualRefID    string          `json:"individualRefID,omitempty"`
	OtherAddress       []OtherAddress  `json:"otherAddress,omitempty"`
	PaxSegmentRefID    string          `json:"paxSegmentRefID,omitempty"`
	Phone              []Phone         `json:"phone,omitempty"`
	PostalAddress      []PostalAddress `json:"postalAddress,omitempty"`
	RelationshipToPax  string          `json:"relationshipToPax,omitempty"`
}

// Main/Root structs - represent the core domain objects
type DistributionChainLink struct {
	ContactInfo            *ContactInfo      `json:"contactInfo,omitempty"`
	Ordinal                int               `json:"ordinal,omitempty"`
	OrgRole                string            `json:"orgRole,omitempty"`
	ParticipatingOrg       *ParticipatingOrg `json:"participatingOrg,omitempty"`
	SalesAgent             *SalesAgent       `json:"salesAgent,omitempty"`
	SalesBranch            *SalesBranch      `json:"salesBranch,omitempty"`
	VerifiablePresentation string            `json:"verifiablePresentation,omitempty"`
}

type DistributionChain struct {
	DistributionChainLink []DistributionChainLink `json:"distributionChainLink,omitempty"`
}
