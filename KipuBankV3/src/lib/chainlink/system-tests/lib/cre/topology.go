package cre

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"

	libc "github.com/smartcontractkit/chainlink/system-tests/lib/conversions"
	"github.com/smartcontractkit/chainlink/v2/core/services/gateway/config"

	"github.com/smartcontractkit/chainlink/system-tests/lib/infra"
)

const (
	OCRPeeringPort          = 5001
	CapabilitiesPeeringPort = 6690
)

type Topology struct {
	WorkflowDONID     uint64        `toml:"workflow_don_id" json:"workflow_don_id"`
	DonsMetadata      *DonsMetadata `toml:"dons_metadata" json:"dons_metadata"`
	GatewayJobConfigs map[NodeUUID]*config.GatewayConfig
	GatewayConnectors *GatewayConnectors `toml:"gateway_connectors" json:"gateway_connectors"`
}

func NewTopology(nodeSet []*NodeSet, provider infra.Provider) (*Topology, error) {
	// TODO this setup is awkward, consider an withInfra opt to constructor
	dm := make([]*DonMetadata, len(nodeSet))
	for i := range nodeSet {
		// TODO take more care about the ID assignment, it should match what the capabilities registry will assign
		// currently we optimistically set the id to the that which the capabilities registry will assign it
		d, err := NewDonMetadata(nodeSet[i], libc.MustSafeUint64FromInt(i+1), provider)
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

	if donsMetadata.RequiresGateway() {
		topology.GatewayConnectors = NewGatewayConnectorOutput()
		for _, d := range donsMetadata.List() {
			if _, hasGateway := d.Gateway(); hasGateway {
				gc, err := d.GatewayConfig(provider)
				if err != nil {
					return nil, fmt.Errorf("failed to get gateway config for DON %s: %w", d.Name, err)
				}
				topology.GatewayConnectors.Configurations = append(topology.GatewayConnectors.Configurations, gc)
			}
		}
	}

	bootstrapNodesFound := 0
	for _, don := range topology.DonsMetadata.List() {
		if _, isBootstrap := don.Bootstrap(); isBootstrap {
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

func (t *Topology) NodeSets() []*NodeSet {
	sets := make([]*NodeSet, len(t.DonsMetadata.List()))
	for i, d := range t.DonsMetadata.List() {
		ns := d.NodeSets()
		sets[i] = ns
	}
	return sets
}

func (t *Topology) DonsMetadataWithFlag(flag CapabilityFlag) []*DonMetadata {
	donsMetadata := make([]*DonMetadata, 0)
	for _, donMetadata := range t.DonsMetadata.List() {
		if !donMetadata.HasFlag(flag) {
			continue
		}
		donsMetadata = append(donsMetadata, donMetadata)
	}

	return donsMetadata
}

// BootstrapNode returns the metadata for the node that should be used as the bootstrap node for P2P peering
// Currently only one bootstrap is supported.
func (t *Topology) Bootstrap() (*NodeMetadata, bool) {
	return t.DonsMetadata.Bootstrap()
}

type PeeringNode interface {
	GetHost() string
	PeerID() string
}

func PeeringCfgs(bt PeeringNode) (CapabilitiesPeeringData, OCRPeeringData, error) {
	p := strings.TrimPrefix(bt.PeerID(), "p2p_")
	if p == "" {
		return CapabilitiesPeeringData{}, OCRPeeringData{}, errors.New("cannot create peering configs, node has no P2P key")
	}
	return CapabilitiesPeeringData{
			GlobalBootstraperPeerID: p,
			GlobalBootstraperHost:   bt.GetHost(),
			Port:                    CapabilitiesPeeringPort,
		}, OCRPeeringData{
			OCRBootstraperPeerID: p,
			OCRBootstraperHost:   bt.GetHost(),
			Port:                 OCRPeeringPort,
		}, nil
}
