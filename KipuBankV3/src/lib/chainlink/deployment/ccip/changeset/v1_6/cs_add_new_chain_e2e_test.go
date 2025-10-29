package v1_6_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chainconfig"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/don_id_claimer"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/ccip_home"
	ccipocr3common "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/stretchr/testify/require"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/globals"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/internal"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/testhelpers"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/v1_6"
	ccipops "github.com/smartcontractkit/chainlink/deployment/ccip/operation/evm/v1_6"
	ccipseq "github.com/smartcontractkit/chainlink/deployment/ccip/sequence/evm/v1_6"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview"

	commonchangeset "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	commoncs "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	"github.com/smartcontractkit/chainlink/deployment/common/proposalutils"
	"github.com/smartcontractkit/chainlink/deployment/common/types"
	cctypes "github.com/smartcontractkit/chainlink/v2/core/capabilities/ccip/types"
)

func checkConnectivity(
	t *testing.T,
	e cldf.Environment,
	state stateview.CCIPOnChainState,
	selector uint64,
	remoteChainSelector uint64,
	expectedRouter *router.Router,
	expectedAllowListEnabled bool,
	expectedRMNVerificationDisabled bool,
) {
	destChainConfig, err := state.Chains[selector].OnRamp.GetDestChainConfig(nil, remoteChainSelector)
	require.NoError(t, err, "must get dest chain config from onRamp")
	require.Equal(t, expectedRouter.Address().Hex(), destChainConfig.Router.Hex(), "router must equal expected")
	require.Equal(t, expectedAllowListEnabled, destChainConfig.AllowlistEnabled, "allowListEnabled must equal expected")

	srcChainConfig, err := state.Chains[selector].OffRamp.GetSourceChainConfig(nil, remoteChainSelector)
	require.NoError(t, err, "must get src chain config from offRamp")
	require.True(t, srcChainConfig.IsEnabled, "src chain config must be enabled")
	require.Equal(t, expectedRMNVerificationDisabled, srcChainConfig.IsRMNVerificationDisabled, "rmnVerificationDisabled must equal expected")
	require.Equal(t, common.LeftPadBytes(state.Chains[remoteChainSelector].OnRamp.Address().Bytes(), 32), srcChainConfig.OnRamp, "remote onRamp must be set on offRamp")
	require.Equal(t, expectedRouter.Address().Hex(), srcChainConfig.Router.Hex(), "router must equal expected")

	isOffRamp, err := expectedRouter.IsOffRamp(nil, remoteChainSelector, state.Chains[selector].OffRamp.Address())
	require.NoError(t, err, "must check if router has offRamp")
	require.True(t, isOffRamp, "router must have offRamp")
	onRamp, err := expectedRouter.GetOnRamp(nil, remoteChainSelector)
	require.NoError(t, err, "must get onRamp from router")
	require.Equal(t, state.Chains[selector].OnRamp.Address().Hex(), onRamp.Hex(), "onRamp must equal expected")
}

func TestConnectNewChain(t *testing.T) {
	t.Parallel()
	mustHaveOwner := func(t *testing.T, ownable commonchangeset.Ownable, expectedOwner string) {
		owner, err := ownable.Owner(nil)
		require.NoError(t, err, "must get owner")
		require.Equal(t, expectedOwner, owner.Hex(), "owner must be "+expectedOwner)
	}

	type test struct {
		Msg                        string
		TransferRemoteChainsToMCMS bool
		TestRouter                 bool
		MCMS                       *proposalutils.TimelockConfig
		ErrStr                     string
	}

	mcmsConfig := &proposalutils.TimelockConfig{
		MinDelay:   0 * time.Second,
		MCMSAction: mcmstypes.TimelockActionSchedule,
	}

	tests := []test{
		{
			Msg:                        "Use production router (with MCMS)",
			TransferRemoteChainsToMCMS: true,
			TestRouter:                 false,
			MCMS:                       mcmsConfig,
		},
		{
			Msg:                        "Use production router (without MCMS)",
			TransferRemoteChainsToMCMS: false,
			TestRouter:                 false,
			MCMS:                       nil,
		},
		{
			Msg:                        "Use test router (with MCMS)",
			TransferRemoteChainsToMCMS: true,
			TestRouter:                 true,
			MCMS:                       mcmsConfig,
		},
		{
			Msg:                        "Use test router (without MCMS)",
			TransferRemoteChainsToMCMS: false,
			TestRouter:                 true,
			MCMS:                       nil,
		},
	}

	for _, test := range tests {
		t.Run(test.Msg, func(t *testing.T) {
			deployedEnvironment, _ := testhelpers.NewMemoryEnvironment(t, func(testCfg *testhelpers.TestConfigs) {
				testCfg.Chains = 3
			})
			e := deployedEnvironment.Env

			state, err := stateview.LoadOnchainState(e)
			require.NoError(t, err, "must load onchain state")

			selectors := e.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyEVM))
			var newSelector uint64
			remoteChainSelectors := make([]uint64, 0, len(selectors)-1)
			for _, selector := range selectors {
				if selector != deployedEnvironment.HomeChainSel && newSelector == 0 {
					newSelector = selector // Just take any non-home chain selector
					continue
				}
				remoteChainSelectors = append(remoteChainSelectors, selector)
			}

			if test.TransferRemoteChainsToMCMS {
				// onRamp, offRamp, and router on non-new chains are assumed to be owned by the timelock
				contractsToTransfer := make(map[uint64][]common.Address, len(remoteChainSelectors))
				for _, selector := range remoteChainSelectors {
					contractsToTransfer[selector] = []common.Address{
						state.Chains[selector].OnRamp.Address(),
						state.Chains[selector].OffRamp.Address(),
						state.Chains[selector].Router.Address(),
					}
				}
				e, err = commonchangeset.Apply(t, e,
					commonchangeset.Configure(
						cldf.CreateLegacyChangeSet(commoncs.TransferToMCMSWithTimelockV2),
						commoncs.TransferToMCMSWithTimelockConfig{
							ContractsByChain: contractsToTransfer,
							MCMSConfig: proposalutils.TimelockConfig{
								MinDelay: 0 * time.Second,
							},
						},
					),
				)
				require.NoError(t, err, "must apply TransferToMCMSWithTimelock")
			}

			remoteChains := make(map[uint64]v1_6.ConnectionConfig, len(remoteChainSelectors))
			for _, selector := range remoteChainSelectors {
				remoteChains[selector] = v1_6.ConnectionConfig{
					RMNVerificationDisabled: false,
					AllowListEnabled:        false,
				}
			}

			e, err = commonchangeset.Apply(t, e,
				commonchangeset.Configure(
					v1_6.ConnectNewChainChangeset,
					v1_6.ConnectNewChainConfig{
						TestRouter:       &test.TestRouter,
						RemoteChains:     remoteChains,
						NewChainSelector: newSelector,
						NewChainConnectionConfig: v1_6.ConnectionConfig{
							RMNVerificationDisabled: true,
							AllowListEnabled:        true,
						},
						MCMSConfig: test.MCMS,
					},
				),
			)
			if test.ErrStr != "" {
				require.ErrorContains(t, err, test.ErrStr, "expected ConnectNewChainChangeset error")
				return
			}
			require.NoError(t, err, "must apply ConnectNewChainChangeset")

			for _, selector := range selectors {
				expectedAllowListEnabled := true
				expectedRMNVerificationDisabled := true
				remoteSelectors := []uint64{newSelector}
				if selector == newSelector {
					expectedAllowListEnabled = false
					expectedRMNVerificationDisabled = false
					remoteSelectors = remoteChainSelectors
					if !test.TestRouter && test.MCMS != nil {
						// New chain must have all contracts owned by timelock
						mustHaveOwner(t, state.Chains[selector].OnRamp, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].OffRamp, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].FeeQuoter, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].RMNProxy, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].NonceManager, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].TokenAdminRegistry, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].Router, state.Chains[selector].Timelock.Address().Hex())
						mustHaveOwner(t, state.Chains[selector].RMNRemote, state.Chains[selector].Timelock.Address().Hex())

						// Admin role for deployer key should be revoked
						adminRole, err := state.Chains[selector].Timelock.ADMINROLE(nil)
						require.NoError(t, err, "must get admin role")
						hasRole, err := state.Chains[selector].Timelock.HasRole(nil, adminRole, e.BlockChains.EVMChains()[selector].DeployerKey.From)
						require.NoError(t, err, "must get admin role")
						require.False(t, hasRole, "deployer key must not have admin role")
					} else {
						// onRamp, offRamp, and router should still be owned by deployer key
						mustHaveOwner(t, state.Chains[selector].OnRamp, e.BlockChains.EVMChains()[selector].DeployerKey.From.Hex())
						mustHaveOwner(t, state.Chains[selector].OffRamp, e.BlockChains.EVMChains()[selector].DeployerKey.From.Hex())
						mustHaveOwner(t, state.Chains[selector].Router, e.BlockChains.EVMChains()[selector].DeployerKey.From.Hex())
					}
				}

				for _, remoteChainSelector := range remoteSelectors {
					expectedRouter := state.Chains[selector].Router
					if test.TestRouter {
						expectedRouter = state.Chains[selector].TestRouter
					}

					checkConnectivity(t, e, state, selector, remoteChainSelector, expectedRouter, expectedAllowListEnabled, expectedRMNVerificationDisabled)
				}
			}
		})
	}
}

func TestAddAndPromoteCandidatesForNewChain(t *testing.T) {
	t.Parallel()
	type test struct {
		Msg         string
		MCMS        *proposalutils.TimelockConfig
		DonIDOffSet *uint32
		ErrStr      string
	}

	offset := uint32(0)

	mcmsConfig := &proposalutils.TimelockConfig{
		MinDelay:   0 * time.Second,
		MCMSAction: mcmstypes.TimelockActionSchedule,
	}

	testRouter := true

	tests := []test{
		{
			Msg:  "Remote chains owned by MCMS",
			MCMS: mcmsConfig,
		},
		{
			Msg:  "Remote chains not owned by MCMS",
			MCMS: nil,
		},
		{
			Msg:         "Remote chains with donID offset (Sync with capReg reg after wrong donIDClaim)",
			DonIDOffSet: &offset,
		},
		{
			Msg:    "fail when multiple reports are enabled and enforce out of order is disabled",
			ErrStr: "EnforceOutOfOrder must be true when MultipleReportsEnabled is true",
		},
	}

	for _, test := range tests {
		t.Run(test.Msg, func(t *testing.T) {
			chainIDs := []uint64{
				chain_selectors.ETHEREUM_MAINNET.EvmChainID,
				chain_selectors.ETHEREUM_MAINNET_ARBITRUM_1.EvmChainID,
				chain_selectors.ETHEREUM_MAINNET_OPTIMISM_1.EvmChainID,
			}

			deployedEnvironment, _ := testhelpers.NewMemoryEnvironment(t, func(testCfg *testhelpers.TestConfigs) {
				testCfg.ChainIDs = chainIDs
			})
			e := deployedEnvironment.Env
			state, err := stateview.LoadOnchainState(e)
			require.NoError(t, err, "must load onchain state")

			// Identify and delete addresses from the new chain
			var newChainSelector uint64
			var linkAddress common.Address
			remoteChainSelectors := make([]uint64, 0, len(chainIDs)-1)
			addressesByChain := make(map[uint64]map[string]cldf.TypeAndVersion, len(chainIDs)-1)
			ds := datastore.NewMemoryDataStore()
			for _, selector := range e.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyEVM)) {
				if selector != deployedEnvironment.HomeChainSel && newChainSelector == 0 {
					newChainSelector = selector
					linkAddress = state.Chains[selector].LinkToken.Address()
				} else {
					remoteChainSelectors = append(remoteChainSelectors, selector)
					addrs, err := e.ExistingAddresses.AddressesForChain(selector)
					require.NoError(t, err, "must get addresses for chain")
					addressesByChain[selector] = addrs
					for addr, tv := range addrs {
						require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
							Address:       addr,
							ChainSelector: selector,
							Labels:        datastore.NewLabelSet(tv.Labels.String()),
							Type:          datastore.ContractType(tv.Type),
							Version:       &tv.Version,
						}))
					}
				}
			}
			e.ExistingAddresses = cldf.NewMemoryAddressBookFromMap(addressesByChain)
			e.DataStore = ds.Seal()
			state, err = stateview.LoadOnchainState(e)
			require.NoError(t, err, "must load onchain state")

			// Identify and delete the DON ID for the new chain
			donID, err := internal.DonIDForChain(
				state.Chains[deployedEnvironment.HomeChainSel].CapabilityRegistry,
				state.Chains[deployedEnvironment.HomeChainSel].CCIPHome,
				newChainSelector,
			)
			require.NoError(t, err, "must get DON ID for chain")
			tx, err := state.Chains[deployedEnvironment.HomeChainSel].CapabilityRegistry.RemoveDONs(
				e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel].DeployerKey,
				[]uint32{donID},
			)
			require.NoError(t, err, "must remove DON ID")
			_, err = e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel].Confirm(tx)
			require.NoError(t, err, "must confirm DON ID removal")

			// Remove chain config on CCIPHome
			tx, err = state.Chains[deployedEnvironment.HomeChainSel].CCIPHome.ApplyChainConfigUpdates(
				e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel].DeployerKey,
				[]uint64{newChainSelector},
				[]ccip_home.CCIPHomeChainConfigArgs{},
			)
			require.NoError(t, err, "must remove chain config from CCIPHome")
			_, err = e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel].Confirm(tx)
			require.NoError(t, err, "must confirm chain config removal")

			// Transfer remote contracts to MCMS if an MCMS config is supplied
			if test.MCMS != nil {
				contractsToTransfer := make(map[uint64][]common.Address, len(remoteChainSelectors))
				for _, selector := range remoteChainSelectors {
					contractsToTransfer[selector] = []common.Address{
						state.Chains[selector].OnRamp.Address(),
						state.Chains[selector].OffRamp.Address(),
						state.Chains[selector].Router.Address(),
						state.Chains[selector].FeeQuoter.Address(),
						state.Chains[selector].RMNProxy.Address(),
						state.Chains[selector].NonceManager.Address(),
						state.Chains[selector].TokenAdminRegistry.Address(),
						state.Chains[selector].RMNRemote.Address(),
					}
				}
				contractsToTransfer[deployedEnvironment.HomeChainSel] = append(
					contractsToTransfer[deployedEnvironment.HomeChainSel],
					state.Chains[deployedEnvironment.HomeChainSel].CCIPHome.Address(),
				)
				contractsToTransfer[deployedEnvironment.HomeChainSel] = append(
					contractsToTransfer[deployedEnvironment.HomeChainSel],
					state.Chains[deployedEnvironment.HomeChainSel].CapabilityRegistry.Address(),
				)
				e, err = commonchangeset.Apply(t, e,
					commonchangeset.Configure(
						cldf.CreateLegacyChangeSet(commoncs.TransferToMCMSWithTimelockV2),
						commoncs.TransferToMCMSWithTimelockConfig{
							ContractsByChain: contractsToTransfer,
							MCMSConfig: proposalutils.TimelockConfig{
								MinDelay: 0 * time.Second,
							},
						},
					),
				)
				require.NoError(t, err, "must apply TransferToMCMSWithTimelock")
			}

			// Build remote chain configurations
			remoteChains := make([]v1_6.ChainDefinition, len(remoteChainSelectors))
			for i, selector := range remoteChainSelectors {
				remoteChains[i] = v1_6.ChainDefinition{
					ConnectionConfig: v1_6.ConnectionConfig{
						RMNVerificationDisabled: true,
						AllowListEnabled:        false,
					},
					Selector:                 selector,
					GasPrice:                 big.NewInt(1e17),
					TokenPrices:              map[common.Address]*big.Int{},
					FeeQuoterDestChainConfig: v1_6.DefaultFeeQuoterDestChainConfig(true),
				}
			}

			// Build new chain configuration
			nodeInfo, err := deployment.NodeInfo(e.NodeIDs, e.Offchain)
			require.NoError(t, err, "must get node info")
			mcmsDeploymentCfg := proposalutils.SingleGroupTimelockConfigV2(t)
			newChain := newChainConfigHelper(newChainSelector, deployedEnvironment.FeedChainSel, linkAddress, &nodeInfo, len(nodeInfo.NonBootstraps().PeerIDs()))

			if test.ErrStr != "" {
				newChain.ExecOCRParams.ExecuteOffChainConfig.MultipleReportsEnabled = true
				remoteChains[0].FeeQuoterDestChainConfig.EnforceOutOfOrder = false
			}

			// deploy donIDClaimer
			e, err = commonchangeset.Apply(t, e,
				commonchangeset.Configure(
					v1_6.DeployDonIDClaimerChangeset,
					v1_6.DeployDonIDClaimerConfig{},
				))
			require.NoError(t, err, "must deploy donIDClaimer contract")

			state, err = stateview.LoadOnchainState(e)
			require.NoError(t, err, "must load onchain state")

			if test.DonIDOffSet != nil {
				tx, err := state.Chains[deployedEnvironment.HomeChainSel].DonIDClaimer.ClaimNextDONId(e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel].DeployerKey)
				require.NoError(t, err)

				_, err = cldf.ConfirmIfNoErrorWithABI(e.BlockChains.EVMChains()[deployedEnvironment.HomeChainSel], tx, don_id_claimer.DonIDClaimerABI, err)
				require.NoError(t, err)
			}

			// Apply AddCandidatesForNewChainChangeset
			e, err = commonchangeset.Apply(t, e,
				commonchangeset.Configure(
					v1_6.AddCandidatesForNewChainChangeset,
					v1_6.AddCandidatesForNewChainConfig{
						HomeChainSelector:    deployedEnvironment.HomeChainSel,
						FeedChainSelector:    deployedEnvironment.FeedChainSel,
						NewChain:             newChain,
						RemoteChains:         remoteChains,
						MCMSDeploymentConfig: &mcmsDeploymentCfg,
						MCMSConfig:           test.MCMS,
						DonIDOffSet:          test.DonIDOffSet,
					},
				),
			)
			if test.ErrStr != "" {
				require.ErrorContains(t, err, test.ErrStr)
				return
			}
			require.NoError(t, err, "must apply AddCandidatesForNewChainChangeset")
			state, err = stateview.LoadOnchainState(e)
			require.NoError(t, err, "must load onchain state")

			capReg := state.Chains[deployedEnvironment.HomeChainSel].CapabilityRegistry
			ccipHome := state.Chains[deployedEnvironment.HomeChainSel].CCIPHome
			rmnProxy := state.Chains[newChainSelector].RMNProxy
			rmnRemote := state.Chains[newChainSelector].RMNRemote
			feeQuoter := state.Chains[newChainSelector].FeeQuoter

			donID, err = internal.DonIDForChain(capReg, ccipHome, newChainSelector)
			require.NoError(t, err, "must get DON ID for chain")

			digests, err := ccipHome.GetConfigDigests(nil, donID, uint8(cctypes.PluginTypeCCIPCommit))
			candidateDigest := digests.CandidateConfigDigest
			require.NoError(t, err, "must get config digests")
			require.Empty(t, digests.ActiveConfigDigest, "active config digest must be empty")

			rmn, err := rmnProxy.GetARM(nil)
			require.NoError(t, err, "must get ARM")
			require.Equal(t, rmnRemote.Address(), rmn, "RMN must be set on RMNProxy")

			for _, remoteChain := range remoteChains {
				destChainConfig, err := feeQuoter.GetDestChainConfig(nil, remoteChain.Selector)
				require.NoError(t, err, "must get dest chain config from feeQuoter")
				require.Equal(t, remoteChain.FeeQuoterDestChainConfig, destChainConfig, "dest chain config must equal expected")

				gasPrice, err := feeQuoter.GetDestinationChainGasPrice(nil, remoteChain.Selector)
				require.NoError(t, err, "must get dest chain gas price from feeQuoter")
				require.Equal(t, remoteChain.GasPrice.String(), gasPrice.Value.String(), "gas price must equal expected")
			}

			// Apply PromoteNewChainForConfigChangeset
			e, err = commonchangeset.Apply(t, e,
				commonchangeset.Configure(
					v1_6.PromoteNewChainForConfigChangeset,
					v1_6.PromoteNewChainForConfig{
						HomeChainSelector: deployedEnvironment.HomeChainSel,
						NewChain:          newChain,
						RemoteChains:      remoteChains,
						TestRouter:        &testRouter,
						MCMSConfig:        test.MCMS,
					},
				),
			)
			require.NoError(t, err, "must apply PromoteNewChainForConfigChangeset")

			digests, err = ccipHome.GetConfigDigests(nil, donID, uint8(cctypes.PluginTypeCCIPCommit))
			require.NoError(t, err, "must get config digests")
			require.Empty(t, digests.CandidateConfigDigest, "candidate config digest must be empty")
			require.Equal(t, candidateDigest, digests.ActiveConfigDigest, "active config digest must equal old candidate digest")

			testRouter := state.Chains[newChain.Selector].TestRouter
			for _, remoteChain := range remoteChains {
				feeQuoterOnRemote := state.Chains[remoteChain.Selector].FeeQuoter
				testRouterOnRemote := state.Chains[remoteChain.Selector].TestRouter

				destChainConfig, err := feeQuoterOnRemote.GetDestChainConfig(nil, newChain.Selector)
				require.NoError(t, err, "must get dest chain config from feeQuoter")
				require.Equal(t, newChain.FeeQuoterDestChainConfig, destChainConfig, "dest chain config must equal expected")

				gasPrice, err := feeQuoterOnRemote.GetDestinationChainGasPrice(nil, newChain.Selector)
				require.NoError(t, err, "must get dest chain gas price from feeQuoter")
				require.Equal(t, newChain.GasPrice.String(), gasPrice.Value.String(), "gas price must equal expected")

				checkConnectivity(t, e, state, remoteChain.Selector, newChain.Selector, testRouterOnRemote, false, true)
				checkConnectivity(t, e, state, newChain.Selector, remoteChain.Selector, testRouter, false, true)
			}

			// Apply ConnectNewChainChangeset to activate on prod routers
			noTestRouter := false
			remoteConnectionConfigs := make(map[uint64]v1_6.ConnectionConfig, len(remoteChainSelectors))
			for _, remoteChain := range remoteChains {
				remoteConnectionConfigs[remoteChain.Selector] = remoteChain.ConnectionConfig
			}
			e, err = commonchangeset.Apply(t, e,
				commonchangeset.Configure(
					v1_6.ConnectNewChainChangeset,
					v1_6.ConnectNewChainConfig{
						NewChainSelector:         newChain.Selector,
						NewChainConnectionConfig: newChain.ConnectionConfig,
						RemoteChains:             remoteConnectionConfigs,
						TestRouter:               &noTestRouter,
						MCMSConfig:               test.MCMS,
					},
				),
			)
			require.NoError(t, err, "must apply ConnectNewChainChangeset")

			router := state.Chains[newChain.Selector].Router
			for _, remoteChain := range remoteChains {
				routerOnRemote := state.Chains[remoteChain.Selector].Router
				checkConnectivity(t, e, state, remoteChain.Selector, newChain.Selector, routerOnRemote, false, true)
				checkConnectivity(t, e, state, newChain.Selector, remoteChain.Selector, router, false, true)
			}
		})
	}
}

func TestRemoveLinkTokenAddressIfExists(t *testing.T) {
	t.Parallel()

	t.Run("should remove LINK token successfully if already exists", func(t *testing.T) {
		deployedEnvironment, _ := testhelpers.NewMemoryEnvironment(t, testhelpers.WithNumOfChains(2))
		e := deployedEnvironment.Env

		selectors := e.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyEVM))
		chainSelector := selectors[0]

		addresses, err := e.ExistingAddresses.AddressesForChain(chainSelector)
		require.NoError(t, err)

		var linkTokenAddr string
		for addr, tv := range addresses {
			if tv.Type == "LinkToken" {
				linkTokenAddr = addr
				break
			}
		}
		require.NotEmpty(t, linkTokenAddr, "should have Link token in the deployed environment")

		existingContracts := commoncs.ExistingContractsConfig{
			ExistingContracts: []commoncs.Contract{
				{
					ChainSelector:  chainSelector,
					Address:        linkTokenAddr,
					TypeAndVersion: cldf.NewTypeAndVersion("LinkToken", deployment.Version1_0_0),
				},
			},
		}

		// This should remove the link token from the existing contracts slice successfully
		err = v1_6.RemoveLinkTokenAddressIfExists(e, &existingContracts)
		require.NoError(t, err, "should remove LinkToken address if exists")

		// Verify the LinkToken was removed from the existing contracts slice
		linkTokenStillExists := false
		for _, contract := range existingContracts.ExistingContracts {
			if contract.TypeAndVersion.Type == "LinkToken" {
				linkTokenStillExists = true
				break
			}
		}
		require.False(t, linkTokenStillExists, "should not have Link token in existing contracts")

		// The address book should remain unchanged
		updatedAddresses, err := e.ExistingAddresses.AddressesForChain(chainSelector)
		require.NoError(t, err)
		linkTokenStillExists = false
		for _, tv := range updatedAddresses {
			if tv.Type == "LinkToken" {
				linkTokenStillExists = true
				break
			}
		}
		require.True(t, linkTokenStillExists, "should still have Link Token in address book")
	})
}

func TestValidateTransmitterAddresses(t *testing.T) {
	t.Parallel()
	t.Run("should fail if the number of transmitter address is less than 3f+1", func(t *testing.T) {
		// Test the core validation logic from ValidateTransmitters method
		// fChain := uint8(1)
		// requiredTransmitters := 3*int(fChain) + 1
		chainIDs := []uint64{
			chain_selectors.ETHEREUM_TESTNET_SEPOLIA.EvmChainID,
			chain_selectors.ETHEREUM_TESTNET_SEPOLIA_ARBITRUM_1.EvmChainID,
			chain_selectors.ETHEREUM_TESTNET_SEPOLIA_OPTIMISM_1.EvmChainID,
		}
		deployedEnvironment, _ := testhelpers.NewMemoryEnvironment(t, func(testCfg *testhelpers.TestConfigs) {
			testCfg.ChainIDs = chainIDs
			testCfg.Nodes = 4
		})
		e := deployedEnvironment.Env
		nodeInfo, err := deployment.NodeInfo(e.NodeIDs, e.Offchain)
		require.NoError(t, err, "must get node info")

		// deploy donIDClaimer
		e, err = commonchangeset.Apply(t, e,
			commonchangeset.Configure(
				v1_6.DeployDonIDClaimerChangeset,
				v1_6.DeployDonIDClaimerConfig{},
			))
		require.NoError(t, err, "must deploy donIDClaimer contract")

		remoteChains := make([]v1_6.ChainDefinition, 1)
		// test
		remoteChains[0] = v1_6.ChainDefinition{
			ConnectionConfig: v1_6.ConnectionConfig{
				RMNVerificationDisabled: true,
				AllowListEnabled:        false,
			},
			Selector:                 chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector,
			GasPrice:                 big.NewInt(1e17),
			TokenPrices:              map[common.Address]*big.Int{},
			FeeQuoterDestChainConfig: v1_6.DefaultFeeQuoterDestChainConfig(true),
		}

		mcmsDeploymentCfg := proposalutils.SingleGroupTimelockConfigV2(t)
		donIDOffSet := uint32(0)
		state, err := stateview.LoadOnchainState(e)
		require.NoError(t, err, "must load onchain state")
		linkAddress := state.Chains[chain_selectors.ETHEREUM_TESTNET_SEPOLIA_OPTIMISM_1.Selector].LinkToken.Address()
		e, err = commonchangeset.Apply(t, e,
			commonchangeset.Configure(
				v1_6.AddCandidatesForNewChainChangeset,
				v1_6.AddCandidatesForNewChainConfig{
					HomeChainSelector:    deployedEnvironment.HomeChainSel,
					FeedChainSelector:    deployedEnvironment.FeedChainSel,
					NewChain:             newChainConfigHelper(chain_selectors.ETHEREUM_TESTNET_SEPOLIA_OPTIMISM_1.Selector, deployedEnvironment.FeedChainSel, linkAddress, &nodeInfo, 6),
					RemoteChains:         remoteChains,
					MCMSDeploymentConfig: &mcmsDeploymentCfg,
					MCMSConfig: &proposalutils.TimelockConfig{
						MinDelay:   0 * time.Second,
						MCMSAction: mcmstypes.TimelockActionSchedule,
					},
					DonIDOffSet: &donIDOffSet,
				},
			),
		)

		require.ErrorContains(t, err, "is less than 3 * fChain + 1")
	})
}

func newChainConfigHelper(newChainSel, feedChainSel uint64, linkTokenAddr common.Address, nodeInfo *deployment.Nodes, noOfPeers int) v1_6.NewChainDefinition {
	return v1_6.NewChainDefinition{
		ChainDefinition: v1_6.ChainDefinition{
			ConnectionConfig: v1_6.ConnectionConfig{
				RMNVerificationDisabled: true,
				AllowListEnabled:        false,
			},
			Selector:                 newChainSel,
			GasPrice:                 big.NewInt(1e17),
			TokenPrices:              map[common.Address]*big.Int{},
			FeeQuoterDestChainConfig: v1_6.DefaultFeeQuoterDestChainConfig(true),
		},
		ChainContractParams: ccipseq.ChainContractParams{
			FeeQuoterParams: ccipops.DefaultFeeQuoterParams(),
			OffRampParams:   ccipops.DefaultOffRampParams(),
		},
		ExistingContracts: commoncs.ExistingContractsConfig{
			ExistingContracts: []commoncs.Contract{
				{
					Address:        linkTokenAddr.Hex(),
					TypeAndVersion: cldf.NewTypeAndVersion(types.LinkToken, deployment.Version1_0_0),
					ChainSelector:  newChainSel,
				},
			},
		},
		ConfigOnHome: v1_6.ChainConfig{
			Readers: nodeInfo.NonBootstraps().PeerIDs(),
			FChain:  uint8(noOfPeers / 3), // #nosec G115 - Overflow is not a concern in this test scenario
			EncodableChainConfig: chainconfig.ChainConfig{
				GasPriceDeviationPPB:    ccipocr3common.BigInt{Int: big.NewInt(testhelpers.DefaultGasPriceDeviationPPB)},
				DAGasPriceDeviationPPB:  ccipocr3common.BigInt{Int: big.NewInt(testhelpers.DefaultDAGasPriceDeviationPPB)},
				OptimisticConfirmations: globals.OptimisticConfirmations,
			},
		},
		CommitOCRParams: v1_6.DeriveOCRParamsForCommit(v1_6.SimulationTest, feedChainSel, nil, nil),
		ExecOCRParams:   v1_6.DeriveOCRParamsForExec(v1_6.SimulationTest, nil, nil),
		// RMNRemoteConfig:   &v1_6.RMNRemoteConfig{...}, // TODO: Enable?
	}
}
