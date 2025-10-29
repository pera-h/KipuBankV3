package changeset_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/stretchr/testify/require"

	cache "github.com/smartcontractkit/chainlink-evm/gethwrappers/data-feeds/generated/data_feeds_cache"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/runtime"

	commonChangesets "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	"github.com/smartcontractkit/chainlink/deployment/common/proposalutils"
	commonTypes "github.com/smartcontractkit/chainlink/deployment/common/types"
	"github.com/smartcontractkit/chainlink/deployment/data-feeds/changeset"
	"github.com/smartcontractkit/chainlink/deployment/data-feeds/changeset/types"
)

func TestSetBundleFeedConfig(t *testing.T) {
	t.Parallel()

	selector := chain_selectors.TEST_90000001.Selector
	rt, err := runtime.New(t.Context(), runtime.WithEnvOpts(
		environment.WithEVMSimulated(t, []uint64{selector}),
	))
	require.NoError(t, err)

	err = rt.Exec(
		runtime.ChangesetTask(changeset.DeployCacheChangeset, types.DeployConfig{
			ChainsToDeploy: []uint64{selector},
			Labels:         []string{"data-feeds"},
		}),
		runtime.ChangesetTask(cldf.CreateLegacyChangeSet(commonChangesets.DeployMCMSWithTimelockV2), map[uint64]commonTypes.MCMSWithTimelockConfigV2{
			selector: proposalutils.SingleGroupTimelockConfigV2(t),
		}),
	)
	require.NoError(t, err)

	records := rt.State().DataStore.Addresses().Filter(datastore.AddressRefByType("DataFeedsCache"))
	require.Len(t, records, 1)
	cacheAddress := records[0].Address

	dataid := "0x01bb0467f50003040000000000000000"

	// without MCMS
	err = rt.Exec(
		runtime.ChangesetTask(changeset.SetFeedAdminChangeset, types.SetFeedAdminConfig{
			ChainSelector: selector,
			CacheAddress:  common.HexToAddress(cacheAddress),
			AdminAddress:  common.HexToAddress(rt.Environment().BlockChains.EVMChains()[selector].DeployerKey.From.Hex()),
			IsAdmin:       true,
		}),
		runtime.ChangesetTask(changeset.SetBundleFeedConfigChangeset, types.SetFeedBundleConfig{
			ChainSelector:  selector,
			CacheAddress:   common.HexToAddress(cacheAddress),
			DataIDs:        []string{dataid},
			Descriptions:   []string{"test"},
			DecimalsMatrix: [][]uint8{{18, 8, 6}},
			WorkflowMetadata: []cache.DataFeedsCacheWorkflowMetadata{
				{
					AllowedSender:        common.HexToAddress("0x22"),
					AllowedWorkflowOwner: common.HexToAddress("0x33"),
					AllowedWorkflowName:  changeset.HashedWorkflowName("test"),
				},
			},
		}),
	)
	require.NoError(t, err)

	// with MCMS
	records = rt.State().DataStore.Addresses().Filter(datastore.AddressRefByType("RBACTimelock"))
	require.Len(t, records, 1)
	timeLockAddress := records[0].Address

	err = rt.Exec(
		runtime.ChangesetTask(changeset.SetFeedAdminChangeset, types.SetFeedAdminConfig{
			ChainSelector: selector,
			CacheAddress:  common.HexToAddress(cacheAddress),
			AdminAddress:  common.HexToAddress(timeLockAddress),
			IsAdmin:       true,
		}),
		runtime.ChangesetTask(cldf.CreateLegacyChangeSet(commonChangesets.TransferToMCMSWithTimelockV2), commonChangesets.TransferToMCMSWithTimelockConfig{
			ContractsByChain: map[uint64][]common.Address{
				selector: {common.HexToAddress(cacheAddress)},
			},
			MCMSConfig: proposalutils.TimelockConfig{MinDelay: 0},
		}),
		runtime.SignAndExecuteProposalsTask([]*ecdsa.PrivateKey{proposalutils.TestXXXMCMSSigner}),
	)
	require.NoError(t, err)
	require.Len(t, rt.State().Proposals, 1)
	require.True(t, rt.State().Proposals[0].IsExecuted)

	// Set the feed config with MCMS
	err = rt.Exec(
		runtime.ChangesetTask(changeset.SetBundleFeedConfigChangeset, types.SetFeedBundleConfig{
			ChainSelector:  selector,
			CacheAddress:   common.HexToAddress(cacheAddress),
			DataIDs:        []string{dataid},
			Descriptions:   []string{"test2"},
			DecimalsMatrix: [][]uint8{{18, 8, 6}},
			WorkflowMetadata: []cache.DataFeedsCacheWorkflowMetadata{
				{
					AllowedSender:        common.HexToAddress("0x22"),
					AllowedWorkflowOwner: common.HexToAddress("0x33"),
					AllowedWorkflowName:  changeset.HashedWorkflowName("test"),
				},
			},
			McmsConfig: &types.MCMSConfig{
				MinDelay: 0,
			},
		}),
		runtime.SignAndExecuteProposalsTask([]*ecdsa.PrivateKey{proposalutils.TestXXXMCMSSigner}),
	)
	require.NoError(t, err)
	require.Len(t, rt.State().Proposals, 2)
	require.True(t, rt.State().Proposals[1].IsExecuted)
}
