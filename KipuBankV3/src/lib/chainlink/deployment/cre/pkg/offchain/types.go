package offchain

import (
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

const (
	FilterKeyDONName      = "don_name"
	FilterKeyCSAPublicKey = "csa_public_key"
)

type TargetDONFilter struct {
	Key   string
	Value string
}

func (f TargetDONFilter) AddToFilter(filter *nodev1.ListNodesRequest_Filter) *nodev1.ListNodesRequest_Filter {
	switch f.Key {
	case FilterKeyDONName:
		filter.Selectors = append(filter.Selectors, &ptypes.Selector{
			Op:  ptypes.SelectorOp_EXIST,
			Key: "don-" + f.Value,
		})
	case FilterKeyCSAPublicKey:
		filter.PublicKeys = append(filter.PublicKeys, f.Value)
	default:
		filter.Selectors = append(filter.Selectors, &ptypes.Selector{
			Op:    ptypes.SelectorOp_EQ,
			Key:   f.Key,
			Value: &f.Value,
		})
	}

	return filter
}

func (f TargetDONFilter) ToListFilter() *nodev1.ListNodesRequest_Filter {
	filter := &nodev1.ListNodesRequest_Filter{}
	return f.AddToFilter(filter)
}
