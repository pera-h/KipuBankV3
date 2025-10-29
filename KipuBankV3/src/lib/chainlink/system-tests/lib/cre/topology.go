package cre

import (
	"fmt"

	"github.com/pkg/errors"

	libc "github.com/smartcontractkit/chainlink/system-tests/lib/conversions"

	"github.com/smartcontractkit/chainlink/system-tests/lib/infra"
)

const (
	OCRPeeringPort          = 5001
	CapabilitiesPeeringPort = 6690
)

var (
	NodeTypeKey            = "type"
	IndexKey               = "node_index"
	ExtraRolesKey          = "extra_roles"
	NodeIDKey              = "node_id"
	NodeOCRFamiliesKey     = "node_ocr_families"
	NodeOCR2KeyBundleIDKey = "ocr2_key_bundle_id"
	DONIDKey               = "don_id"
	EnvironmentKey         = "environment"
	ProductKey             = "product"
	DONNameKey             = "don_name"
)

type Topology struct {
	WorkflowDONID          uint64                  `toml:"workflow_don_id" json:"workflow_don_id"`
	DonsMetadata           *DonsMetadata           `toml:"dons_metadata" json:"dons_metadata"`
	GatewayConnectorOutput *GatewayConnectorOutput `toml:"gateway_connector_output" json:"gateway_connector_output"`
}

func NewTopology(nodeSetInput []*CapabilitiesAwareNodeSet, provider infra.Provider) (*Topology, error) {
	// TODO this setup is awkward, consider an withInfra opt to constructor
	dm := make([]*DonMetadata, len(nodeSetInput))
	for i := range nodeSetInput {
		// TODO take more care about the ID assignment, it should match what the capabilities registry will assign
		// currently we optimistically set the id to the that which the capabilities registry will assign it
		d, err := NewDonMetadata(nodeSetInput[i], libc.MustSafeUint64FromInt(i+1), provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create DON metadata: %w", err)
		}
		dm[i] = d
	}

	donsMetadata, err := NewDonsMetadata(dm, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DONs metadata: %w", err)
	}

	wfDon, err := donsMetadata.WorkflowDON()
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow DON: %w", err)
	}

	topology := &Topology{
		WorkflowDONID: wfDon.ID,
		DonsMetadata:  donsMetadata,
	}

	if donsMetadata.GatewayRequired() {
		topology.GatewayConnectorOutput = NewGatewayConnectorOutput()
		for _, d := range donsMetadata.List() {
			if d.ContainsGatewayNode() {
				gc, err := d.GatewayConfig(provider)
				if err != nil {
					return nil, fmt.Errorf("failed to get gateway config for DON %s: %w", d.Name, err)
				}
				topology.GatewayConnectorOutput.Configurations = append(topology.GatewayConnectorOutput.Configurations, gc)
			}
		}
	}

	bootstrapNodesFound := 0
	for _, don := range topology.DonsMetadata.List() {
		if don.ContainsBootstrapNode() {
			bootstrapNodesFound++
		}
	}

	if bootstrapNodesFound == 0 {
		return nil, errors.New("no bootstrap nodes found in topology. At least one bootstrap node is required")
	}

	if bootstrapNodesFound > 1 {
		return nil, errors.New("multiple bootstrap nodes found in topology. Only one bootstrap node is supported due to the limitations of the local environment")
	}

	return topology, nil
}

func (t *Topology) CapabilitiesAwareNodeSets() []*CapabilitiesAwareNodeSet {
	sets := make([]*CapabilitiesAwareNodeSet, len(t.DonsMetadata.List()))
	for i, d := range t.DonsMetadata.List() {
		ns := d.CapabilitiesAwareNodeSet()
		sets[i] = ns
	}
	return sets
}

// BootstrapNode returns the metadata for the node that should be used as the bootstrap node for P2P peering
// Currently only one bootstrap is supported.
func (t *Topology) BootstrapNode() (*NodeMetadata, error) {
	return t.DonsMetadata.BootstrapNode()
}

func PeeringCfgs(bt *NodeMetadata) (CapabilitiesPeeringData, OCRPeeringData, error) {
	p := bt.Keys.CleansedPeerID()
	if p == "" {
		return CapabilitiesPeeringData{}, OCRPeeringData{}, errors.New("cannot create peering configs, node has no P2P key")
	}
	return CapabilitiesPeeringData{
			GlobalBootstraperPeerID: p,
			GlobalBootstraperHost:   bt.Host,
			Port:                    CapabilitiesPeeringPort,
		}, OCRPeeringData{
			OCRBootstraperPeerID: p,
			OCRBootstraperHost:   bt.Host,
			Port:                 OCRPeeringPort,
		}, nil
}
