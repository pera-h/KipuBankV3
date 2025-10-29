package stateview

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/Masterminds/semver/v3"
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/ccip-contract-examples/chains/evm/gobindings/generated/latest/burn_mint_with_external_minter_token_pool"
	"github.com/smartcontractkit/ccip-contract-examples/chains/evm/gobindings/generated/latest/hybrid_with_external_minter_token_pool"
	"github.com/smartcontractkit/ccip-contract-examples/chains/evm/gobindings/generated/latest/token_governor"
	"github.com/smartcontractkit/ccip-owner-contracts/pkg/gethwrappers"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/don_id_claimer"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/factory_burn_mint_erc20"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fast_transfer_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/log_message_data_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/maybe_revert_message_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/mock_usdc_token_messenger"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/mock_usdc_token_transmitter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_0_0/rmn_proxy_contract"
	price_registry_1_2_0 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/price_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/commit_store"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/evm_2_evm_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/evm_2_evm_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/mock_rmn_contract"
	registryModuleOwnerCustomv15 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/registry_module_owner_custom"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/rmn_contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/burn_from_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/burn_with_from_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/token_pool_factory"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_1/usdc_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/ccip_home"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/nonce_manager"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/onramp"
	registryModuleOwnerCustomv16 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/registry_module_owner_custom"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_home"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_2/cctp_message_transmitter_proxy"
	usdc_token_pool_v1_6_2 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_2/usdc_token_pool"
	solOffRamp "github.com/smartcontractkit/chainlink-ccip/chains/solana/gobindings/v0_1_1/ccip_offramp"
	solState "github.com/smartcontractkit/chainlink-ccip/chains/solana/utils/state"
	cldf_evm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	cldf_chain_utils "github.com/smartcontractkit/chainlink-deployments-framework/chain/utils"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/generated/link_token_interface"
	capabilities_registry "github.com/smartcontractkit/chainlink-evm/gethwrappers/keystone/generated/capabilities_registry_1_1_0"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/aggregator_v3_interface"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc20"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc677"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc677"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/link_token"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/multicall3"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/weth9"
	tonstate "github.com/smartcontractkit/chainlink-ton/deployment/state"
	"github.com/smartcontractkit/chainlink-ton/pkg/ccip/codec"
	"github.com/smartcontractkit/chainlink/deployment"
	ccipshared "github.com/smartcontractkit/chainlink/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/bindings/burn_mint_with_external_minter_fast_transfer_token_pool"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/bindings/hybrid_with_external_minter_fast_transfer_token_pool"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/bindings/signer_registry"
	aptosstate "github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview/aptos"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview/evm"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview/solana"
	"github.com/smartcontractkit/chainlink/deployment/ccip/view"
	commoncs "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	commonstate "github.com/smartcontractkit/chainlink/deployment/common/changeset/state"
	"github.com/smartcontractkit/chainlink/deployment/common/proposalutils"
	commontypes "github.com/smartcontractkit/chainlink/deployment/common/types"
	"github.com/smartcontractkit/chainlink/deployment/helpers"
)

const chainNotSupportedErr = "chain not supported"

// CCIPOnChainState state always derivable from an address book.
// Offchain state always derivable from a list of nodeIds.
// Note can translate this into Go struct needed for MCMS/Docs/UI.
type CCIPOnChainState struct {
	// Populated go bindings for the appropriate version for all contracts.
	// We would hold 2 versions of each contract here. Once we upgrade we can phase out the old one.
	// When generating bindings, make sure the package name corresponds to the version.
	Chains      map[uint64]evm.CCIPChainState
	SolChains   map[uint64]solana.CCIPChainState
	AptosChains map[uint64]aptosstate.CCIPChainState
	TonChains   map[uint64]tonstate.CCIPChainState
	evmMu       *sync.RWMutex
}

type CCIPStateView struct {
	Chains      map[string]view.ChainView
	SolChains   map[string]view.SolChainView
	AptosChains map[string]view.AptosChainView
	TONChains   map[string]tonstate.TONChainView
}

func (c CCIPOnChainState) EVMChains() []uint64 {
	c.evmMu.RLock()
	defer c.evmMu.RUnlock()
	return maps.Keys(c.Chains)
}

func (c CCIPOnChainState) EVMChainState(selector uint64) (evm.CCIPChainState, bool) {
	c.evmMu.RLock()
	defer c.evmMu.RUnlock()
	chainState, ok := c.Chains[selector]
	return chainState, ok
}

func (c CCIPOnChainState) MustGetEVMChainState(selector uint64) evm.CCIPChainState {
	c.evmMu.RLock()
	defer c.evmMu.RUnlock()
	chainState, ok := c.Chains[selector]
	if !ok {
		panic("chain state not found for selector " + strconv.FormatUint(selector, 10))
	}
	return chainState
}

func (c CCIPOnChainState) WriteEVMChainState(selector uint64, chainState evm.CCIPChainState) {
	c.evmMu.Lock()
	defer c.evmMu.Unlock()
	c.Chains[selector] = chainState
}

// ValidatePostDeploymentState should be called after the deployment and configuration for all contracts
// in environment is complete.
// It validates the state of the contracts and ensures that they are correctly configured and wired with each other.
func (c CCIPOnChainState) ValidatePostDeploymentState(e cldf.Environment, validateHomeChain bool) error {
	onRampsBySelector := make(map[uint64]common.Address)
	offRampsBySelector := make(map[uint64]offramp.OffRampInterface)
	for _, selector := range c.EVMChains() {
		chainState := c.MustGetEVMChainState(selector)
		if chainState.OnRamp == nil {
			return fmt.Errorf("onramp not found in the state for chain %d", selector)
		}
		onRampsBySelector[selector] = chainState.OnRamp.Address()
		offRampsBySelector[selector] = chainState.OffRamp
	}
	nodes, err := deployment.NodeInfo(e.NodeIDs, e.Offchain)
	if err != nil {
		return fmt.Errorf("failed to get node info from env: %w", err)
	}
	homeChain, err := c.HomeChainSelector()
	if err != nil {
		return fmt.Errorf("failed to get home chain selector: %w", err)
	}
	homeChainState := c.MustGetEVMChainState(homeChain)
	if validateHomeChain {
		if err := homeChainState.ValidateHomeChain(e, nodes, offRampsBySelector); err != nil {
			return fmt.Errorf("failed to validate home chain %d: %w", homeChain, err)
		}
	}
	rmnHomeActiveDigest, err := homeChainState.RMNHome.GetActiveDigest(&bind.CallOpts{
		Context: e.GetContext(),
	})
	if err != nil {
		return fmt.Errorf("failed to get active digest for RMNHome %s at home chain %d: %w", homeChainState.RMNHome.Address().Hex(), homeChain, err)
	}
	isRMNEnabledInRMNHomeBySourceChain := make(map[uint64]bool)
	rmnHomeConfig, err := homeChainState.RMNHome.GetConfig(&bind.CallOpts{
		Context: e.GetContext(),
	}, rmnHomeActiveDigest)
	if err != nil {
		return fmt.Errorf("failed to get config for RMNHome %s at home chain %d: %w", homeChainState.RMNHome.Address().Hex(), homeChain, err)
	}
	// if Fobserve is greater than 0, RMN is enabled for the source chain in RMNHome
	for _, rmnHomeChain := range rmnHomeConfig.VersionedConfig.DynamicConfig.SourceChains {
		isRMNEnabledInRMNHomeBySourceChain[rmnHomeChain.ChainSelector] = rmnHomeChain.FObserve > 0
	}
	for _, selector := range c.EVMChains() {
		chainState := c.MustGetEVMChainState(selector)
		isRMNEnabledInRmnRemote, err := chainState.ValidateRMNRemote(e, selector, rmnHomeActiveDigest)
		if err != nil {
			return fmt.Errorf("failed to validate RMNRemote %s for chain %d: %w", chainState.RMNRemote.Address().Hex(), selector, err)
		}
		// check whether RMNRemote and RMNHome are in sync in terms of RMNEnabled
		if isRMNEnabledInRmnRemote != isRMNEnabledInRMNHomeBySourceChain[selector] {
			return fmt.Errorf("RMNRemote %s rmnEnabled mismatch with RMNHome for chain %d: expected %v, got %v",
				chainState.RMNRemote.Address().Hex(), selector, isRMNEnabledInRMNHomeBySourceChain[selector], isRMNEnabledInRmnRemote)
		}
		otherOnRamps := make(map[uint64]common.Address)
		isTestRouter := true
		if chainState.Router != nil {
			isTestRouter = false
		}
		connectedChains, err := chainState.ValidateRouter(e, isTestRouter)
		if err != nil {
			return fmt.Errorf("failed to validate router %s for chain %d: %w", chainState.Router.Address().Hex(), selector, err)
		}
		for _, connectedChain := range connectedChains {
			if connectedChain == selector {
				continue
			}
			otherOnRamps[connectedChain] = c.MustGetEVMChainState(connectedChain).OnRamp.Address()
		}
		if err := chainState.ValidateOffRamp(e, selector, otherOnRamps, isRMNEnabledInRMNHomeBySourceChain); err != nil {
			return fmt.Errorf("failed to validate offramp %s for chain %d: %w", chainState.OffRamp.Address().Hex(), selector, err)
		}
		if err := chainState.ValidateOnRamp(e, selector, connectedChains); err != nil {
			return fmt.Errorf("failed to validate onramp %s for chain %d: %w", chainState.OnRamp.Address().Hex(), selector, err)
		}
		if err := chainState.ValidateFeeQuoter(e); err != nil {
			return fmt.Errorf("failed to validate fee quoter %s for chain %d: %w", chainState.FeeQuoter.Address().Hex(), selector, err)
		}
	}
	return nil
}

// HomeChainSelector returns the selector of the home chain based on the presence of RMNHome, CapabilityRegistry and CCIPHome contracts.
func (c CCIPOnChainState) HomeChainSelector() (uint64, error) {
	for _, selector := range c.EVMChains() {
		chain := c.MustGetEVMChainState(selector)
		if chain.RMNHome != nil && chain.CapabilityRegistry != nil && chain.CCIPHome != nil {
			return selector, nil
		}
	}
	return 0, errors.New("no home chain found")
}

func (c CCIPOnChainState) EVMMCMSStateByChain() map[uint64]commonstate.MCMSWithTimelockState {
	mcmsStateByChain := make(map[uint64]commonstate.MCMSWithTimelockState)
	for _, chainSelector := range c.EVMChains() {
		chain := c.MustGetEVMChainState(chainSelector)
		mcmsStateByChain[chainSelector] = commonstate.MCMSWithTimelockState{
			CancellerMcm: chain.CancellerMcm,
			BypasserMcm:  chain.BypasserMcm,
			ProposerMcm:  chain.ProposerMcm,
			Timelock:     chain.Timelock,
			CallProxy:    chain.CallProxy,
		}
	}
	return mcmsStateByChain
}

func (c CCIPOnChainState) SolanaMCMSStateByChain(e cldf.Environment) map[uint64]commonstate.MCMSWithTimelockStateSolana {
	mcmsStateByChain := make(map[uint64]commonstate.MCMSWithTimelockStateSolana)
	for chainSelector := range e.BlockChains.SolanaChains() {
		addreses, err := e.ExistingAddresses.AddressesForChain(chainSelector)
		if err != nil {
			return mcmsStateByChain
		}
		mcmState, err := commonstate.MaybeLoadMCMSWithTimelockChainStateSolana(e.BlockChains.SolanaChains()[chainSelector], addreses)
		if err != nil {
			return mcmsStateByChain
		}
		mcmsStateByChain[chainSelector] = *mcmState
	}
	return mcmsStateByChain
}

func (c CCIPOnChainState) AptosMCMSStateByChain() map[uint64]aptos.AccountAddress {
	mcmsByChain := make(map[uint64]aptos.AccountAddress)
	for chainSelector, state := range c.AptosChains {
		mcmsByChain[chainSelector] = state.MCMSAddress
	}
	return mcmsByChain
}

func (c CCIPOnChainState) OffRampPermissionLessExecutionThresholdSeconds(ctx context.Context, env cldf.Environment, selector uint64) (uint32, error) {
	family, err := chain_selectors.GetSelectorFamily(selector)
	if err != nil {
		return 0, err
	}
	switch family {
	case chain_selectors.FamilyEVM:
		chain, ok := c.EVMChainState(selector)
		if !ok {
			return 0, fmt.Errorf("chain %d not found in the state", selector)
		}
		offRamp := chain.OffRamp
		if offRamp == nil {
			return 0, fmt.Errorf("offramp not found in the state for chain %d", selector)
		}
		dCfg, err := offRamp.GetDynamicConfig(&bind.CallOpts{
			Context: ctx,
		})
		if err != nil {
			return dCfg.PermissionLessExecutionThresholdSeconds, fmt.Errorf("fetch dynamic config from offRamp %s for chain %d: %w", offRamp.Address().String(), selector, err)
		}
		return dCfg.PermissionLessExecutionThresholdSeconds, nil
	case chain_selectors.FamilySolana:
		chainState, ok := c.SolChains[selector]
		if !ok {
			return 0, fmt.Errorf("chain %d not found in the state", selector)
		}
		chain, ok := env.BlockChains.SolanaChains()[selector]
		if !ok {
			return 0, fmt.Errorf("solana chain %d not found in the environment", selector)
		}
		if chainState.OffRamp.IsZero() {
			return 0, fmt.Errorf("offramp not found in existing state, deploy the offramp first for chain %d", selector)
		}
		var offRampConfig solOffRamp.Config
		offRampConfigPDA, _, _ := solState.FindOfframpConfigPDA(chainState.OffRamp)
		err := chain.GetAccountDataBorshInto(context.Background(), offRampConfigPDA, &offRampConfig)
		if err != nil {
			return 0, fmt.Errorf("offramp config not found in existing state, initialize the offramp first %d", chain.Selector)
		}
		// #nosec G115
		return uint32(offRampConfig.EnableManualExecutionAfter), nil
	case chain_selectors.FamilyAptos:
		chainState, ok := c.AptosChains[selector]
		if !ok {
			return 0, fmt.Errorf("chain %d does not exist in state", selector)
		}
		chain, ok := env.BlockChains.AptosChains()[selector]
		if !ok {
			return 0, fmt.Errorf("chain %d does not exist in env", selector)
		}
		if chainState.CCIPAddress == (aptos.AccountAddress{}) {
			return 0, fmt.Errorf("ccip not found in existing state, deploy the ccip first for Aptos chain %d", selector)
		}
		offrampDynamicConfig, err := aptosstate.GetOfframpDynamicConfig(chain, chainState.CCIPAddress)
		if err != nil {
			return 0, fmt.Errorf("failed to get offramp dynamic config for Aptos chain %d: %w", selector, err)
		}
		return offrampDynamicConfig.PermissionlessExecutionThresholdSeconds, nil
	}
	return 0, fmt.Errorf("unsupported chain family %s", family)
}

func (c CCIPOnChainState) Validate() error {
	for _, sel := range c.EVMChains() {
		chain := c.MustGetEVMChainState(sel)
		// cannot have static link and link together
		if chain.LinkToken != nil && chain.StaticLinkToken != nil {
			return fmt.Errorf("cannot have both link and static link token on the same chain %d", sel)
		}
	}
	return nil
}

func (c CCIPOnChainState) GetAllProposerMCMSForChains(chains []uint64) (map[uint64]*gethwrappers.ManyChainMultiSig, error) {
	multiSigs := make(map[uint64]*gethwrappers.ManyChainMultiSig)
	for _, chain := range chains {
		chainState, ok := c.EVMChainState(chain)
		if !ok {
			return nil, fmt.Errorf("chain %d not found", chain)
		}
		if chainState.ProposerMcm == nil {
			return nil, fmt.Errorf("proposer mcm not found for chain %d", chain)
		}
		multiSigs[chain] = chainState.ProposerMcm
	}
	return multiSigs, nil
}

func (c CCIPOnChainState) GetAllTimeLocksForChains(chains []uint64) (map[uint64]common.Address, error) {
	timelocks := make(map[uint64]common.Address)
	for _, chain := range chains {
		chainState, ok := c.EVMChainState(chain)
		if !ok {
			return nil, fmt.Errorf("chain %d not found", chain)
		}
		if chainState.Timelock == nil {
			return nil, fmt.Errorf("timelock not found for chain %d", chain)
		}
		timelocks[chain] = chainState.Timelock.Address()
	}
	return timelocks, nil
}

func (c CCIPOnChainState) SupportedChains() map[uint64]struct{} {
	chains := make(map[uint64]struct{})
	for _, chain := range c.EVMChains() {
		chains[chain] = struct{}{}
	}
	for chain := range c.SolChains {
		chains[chain] = struct{}{}
	}
	for chain := range c.AptosChains {
		chains[chain] = struct{}{}
	}
	for chain := range c.TonChains {
		chains[chain] = struct{}{}
	}
	return chains
}

// EnforceMCMSUsageIfProd determines if an MCMS config should be enforced for this particular environment.
// It checks if the CCIPHome and CapabilitiesRegistry contracts are owned by the Timelock because all other contracts should follow this precedent.
// If the home chain contracts are owned by the Timelock and no mcmsConfig is provided, this function will return an error.
func (c CCIPOnChainState) EnforceMCMSUsageIfProd(ctx context.Context, mcmsConfig *proposalutils.TimelockConfig) error {
	// Instead of accepting a homeChainSelector, we simply look for the CCIPHome and CapabilitiesRegistry in state.
	// This is because the home chain selector is not always available in the input to a changeset.
	// Also, if the underlying rules to EnforceMCMSUsageIfProd change (i.e. what determines "prod" changes),
	// we can simply update the function body without worrying about the function signature.
	var ccipHome *ccip_home.CCIPHome
	var capReg *capabilities_registry.CapabilitiesRegistry
	var homeChainSelector uint64
	for _, selector := range c.EVMChains() {
		chain := c.MustGetEVMChainState(selector)
		if chain.CCIPHome == nil || chain.CapabilityRegistry == nil {
			continue
		}
		// This condition impacts the ability of this function to determine MCMS enforcement.
		// As such, we return an error if we find multiple chains with home chain contracts.
		if ccipHome != nil {
			return errors.New("multiple chains with CCIPHome and CapabilitiesRegistry contracts found")
		}
		ccipHome = chain.CCIPHome
		capReg = chain.CapabilityRegistry
		homeChainSelector = selector
	}
	// It is not the job of this function to enforce the existence of home chain contracts.
	// Some tests don't deploy these contracts, and we don't want to fail them.
	// We simply say that MCMS is not enforced in such environments.
	if ccipHome == nil {
		return nil
	}
	// If the timelock contract is not found on the home chain,
	// we know that MCMS is not enforced.
	timelock := c.MustGetEVMChainState(homeChainSelector).Timelock
	if timelock == nil {
		return nil
	}
	ccipHomeOwner, err := ccipHome.Owner(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("failed to get CCIP home owner: %w", err)
	}
	capRegOwner, err := capReg.Owner(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("failed to get capabilities registry owner: %w", err)
	}
	if ccipHomeOwner != capRegOwner {
		return fmt.Errorf("CCIPHome and CapabilitiesRegistry owners do not match: %s != %s", ccipHomeOwner.String(), capRegOwner.String())
	}
	// If CCIPHome & CapabilitiesRegistry are owned by timelock, then MCMS is enforced.
	if ccipHomeOwner == timelock.Address() && mcmsConfig == nil {
		return errors.New("MCMS is enforced for environment (i.e. CCIPHome & CapReg are owned by timelock), but no MCMS config was provided")
	}

	return nil
}

// ValidateOwnershipOfChain validates the ownership of every CCIP contract on a chain.
// If mcmsConfig is nil, the expected owner of each contract is the chain's deployer key.
// If provided, the expected owner is the Timelock contract.
func (c CCIPOnChainState) ValidateOwnershipOfChain(e cldf.Environment, chainSel uint64, mcmsConfig *proposalutils.TimelockConfig) error {
	chain, ok := e.BlockChains.EVMChains()[chainSel]
	if !ok {
		return fmt.Errorf("chain with selector %d not found in the environment", chainSel)
	}

	chainState, ok := c.EVMChainState(chainSel)
	if !ok {
		return fmt.Errorf("%s not found in the state", chain)
	}
	if chainState.Timelock == nil {
		return fmt.Errorf("timelock not found on %s", chain)
	}

	ownedContracts := map[string]commoncs.Ownable{
		"router":             chainState.Router,
		"feeQuoter":          chainState.FeeQuoter,
		"offRamp":            chainState.OffRamp,
		"onRamp":             chainState.OnRamp,
		"nonceManager":       chainState.NonceManager,
		"rmnRemote":          chainState.RMNRemote,
		"rmnProxy":           chainState.RMNProxy,
		"tokenAdminRegistry": chainState.TokenAdminRegistry,
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(ownedContracts))
	for contractName, contract := range ownedContracts {
		wg.Add(1)
		go func(name string, c commoncs.Ownable) {
			defer wg.Done()
			if c == nil {
				errs <- fmt.Errorf("missing %s contract on %s", name, chain)
				return
			}
			err := commoncs.ValidateOwnership(e.GetContext(), mcmsConfig != nil, chain.DeployerKey.From, chainState.Timelock.Address(), contract)
			if err != nil {
				errs <- fmt.Errorf("failed to validate ownership of %s contract on %s: %w", name, chain, err)
			}
		}(contractName, contract)
	}
	wg.Wait()
	close(errs)
	var multiErr error
	for err := range errs {
		multiErr = errors.Join(multiErr, err)
	}
	if multiErr != nil {
		return multiErr
	}

	return nil
}

func (c CCIPOnChainState) View(e *cldf.Environment, chains []uint64) (CCIPStateView, error) {
	m := sync.Map{}
	sm := sync.Map{}
	am := sync.Map{}
	tm := sync.Map{}

	// Create worker pool with fixed number of goroutines
	const numWorkers = 8
	jobCh := make(chan uint64, len(chains))
	grp := errgroup.Group{}

	// Start fixed number of workers
	for i := 0; i < numWorkers; i++ {
		grp.Go(func() error {
			for chainSelector := range jobCh {
				var name string
				family, err := chain_selectors.GetSelectorFamily(chainSelector)
				if err != nil {
					return err
				}
				chainInfo, err := cldf_chain_utils.ChainInfo(chainSelector)
				if err != nil {
					return err
				}
				name = chainInfo.ChainName
				if chainInfo.ChainName == "" {
					name = strconv.FormatUint(chainSelector, 10)
				}
				id, err := chain_selectors.GetChainIDFromSelector(chainSelector)
				if err != nil {
					return fmt.Errorf("failed to get chain id from selector %d: %w", chainSelector, err)
				}
				e.Logger.Infow("Generating view for", "chainSelector", chainSelector, "chainName", name, "chainID", id)
				switch family {
				case chain_selectors.FamilyEVM:
					if _, ok := c.EVMChainState(chainSelector); !ok {
						return fmt.Errorf("%s %d", chainNotSupportedErr, chainSelector)
					}
					chainState := c.MustGetEVMChainState(chainSelector)
					chainView, err := chainState.GenerateView(e.Logger, name)
					if err != nil {
						return err
					}
					chainView.ChainSelector = chainSelector
					chainView.ChainID = id
					m.Store(name, chainView)
					e.Logger.Infow("Completed view for", "chainSelector", chainSelector, "chainName", name, "chainID", id)
				case chain_selectors.FamilySolana:
					if _, ok := c.SolChains[chainSelector]; !ok {
						return fmt.Errorf("%s %d", chainNotSupportedErr, chainSelector)
					}
					chainState := c.SolChains[chainSelector]
					chainView, err := chainState.GenerateView(e, chainSelector)
					if err != nil {
						return err
					}
					chainView.ChainSelector = chainSelector
					chainView.ChainID = id
					sm.Store(name, chainView)
				case chain_selectors.FamilyAptos:
					chainState, ok := c.AptosChains[chainSelector]
					if !ok {
						return fmt.Errorf("%s %d", chainNotSupportedErr, chainSelector)
					}
					chainView, err := chainState.GenerateView(e, chainSelector, name)
					if err != nil {
						return err
					}
					chainView.ChainSelector = chainSelector
					chainView.ChainID = id
					am.Store(name, chainView)
				case chain_selectors.FamilyTon:
					if _, ok := c.TonChains[chainSelector]; !ok {
						return fmt.Errorf("%s %d", chainNotSupportedErr, chainSelector)
					}
					chainState := c.TonChains[chainSelector]
					chainView, err := chainState.GenerateView(e, chainSelector, name)
					if err != nil {
						return err
					}
					tm.Store(name, chainView)
				default:
					return fmt.Errorf("unsupported chain family %s", family)
				}
			}
			return nil
		})
	}

	// Send jobs to workers
	for _, chainSelector := range chains {
		jobCh <- chainSelector
	}
	close(jobCh)

	if err := grp.Wait(); err != nil {
		return CCIPStateView{}, err
	}
	stateView := CCIPStateView{
		Chains:      make(map[string]view.ChainView),
		SolChains:   make(map[string]view.SolChainView),
		AptosChains: make(map[string]view.AptosChainView),
		TONChains:   make(map[string]tonstate.TONChainView),
	}
	m.Range(func(key, value interface{}) bool {
		stateView.Chains[key.(string)] = value.(view.ChainView)
		return true
	})
	sm.Range(func(key, value interface{}) bool {
		stateView.SolChains[key.(string)] = value.(view.SolChainView)
		return true
	})
	am.Range(func(key, value interface{}) bool {
		stateView.AptosChains[key.(string)] = value.(view.AptosChainView)
		return true
	})
	tm.Range(func(key, value interface{}) bool {
		stateView.TONChains[key.(string)] = value.(tonstate.TONChainView)
		return true
	})
	return stateView, grp.Wait()
}

func (c CCIPOnChainState) GetOffRampAddressBytes(chainSelector uint64) ([]byte, error) {
	family, err := chain_selectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return nil, err
	}

	var offRampAddress []byte
	switch family {
	case chain_selectors.FamilyEVM:
		offRampAddress = c.MustGetEVMChainState(chainSelector).OffRamp.Address().Bytes()
	case chain_selectors.FamilySolana:
		offRampAddress = c.SolChains[chainSelector].OffRamp.Bytes()
	case chain_selectors.FamilyAptos:
		ccipAddress := c.AptosChains[chainSelector].CCIPAddress
		offRampAddress = ccipAddress[:]
	case chain_selectors.FamilyTon:
		or := c.TonChains[chainSelector].OffRamp
		rawBytes := codec.ToRawAddr(&or)
		offRampAddress = rawBytes[:]

	default:
		return nil, fmt.Errorf("unsupported chain family %s", family)
	}

	return offRampAddress, nil
}

func (c CCIPOnChainState) GetOnRampAddressBytes(chainSelector uint64) ([]byte, error) {
	family, err := chain_selectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return nil, err
	}

	var onRampAddressBytes []byte
	switch family {
	case chain_selectors.FamilyEVM:
		if c.MustGetEVMChainState(chainSelector).OnRamp == nil {
			return nil, fmt.Errorf("no onramp found in the state for chain %d", chainSelector)
		}
		onRampAddressBytes = c.MustGetEVMChainState(chainSelector).OnRamp.Address().Bytes()
	case chain_selectors.FamilySolana:
		if c.SolChains[chainSelector].Router.IsZero() {
			return nil, fmt.Errorf("no router found in the state for chain %d", chainSelector)
		}
		onRampAddressBytes = c.SolChains[chainSelector].Router.Bytes()
	case chain_selectors.FamilyAptos:
		ccipAddress := c.AptosChains[chainSelector].CCIPAddress
		if ccipAddress == (aptos.AccountAddress{}) {
			return nil, fmt.Errorf("no ccip address found in the state for Aptos chain %d", chainSelector)
		}
		onRampAddressBytes = ccipAddress[:]
	case chain_selectors.FamilyTon:
		ramp := c.TonChains[chainSelector].OnRamp
		if ramp.IsAddrNone() {
			return nil, fmt.Errorf("no onramp found in the state for TON chain %d", chainSelector)
		}
		rawAddress := codec.ToRawAddr(&ramp)
		onRampAddressBytes = rawAddress[:]

	default:
		return nil, fmt.Errorf("unsupported chain family %s", family)
	}

	return onRampAddressBytes, nil
}

func (c CCIPOnChainState) ValidateRamp(chainSelector uint64, rampType cldf.ContractType) error {
	family, err := chain_selectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return err
	}
	switch family {
	case chain_selectors.FamilyEVM:
		chainState, exists := c.EVMChainState(chainSelector)
		if !exists {
			return fmt.Errorf("chain %d does not exist", chainSelector)
		}
		switch rampType {
		case ccipshared.OffRamp:
			if chainState.OffRamp == nil {
				return fmt.Errorf("offramp contract does not exist on evm chain %d", chainSelector)
			}
		case ccipshared.OnRamp:
			if chainState.OnRamp == nil {
				return fmt.Errorf("onramp contract does not exist on evm chain %d", chainSelector)
			}
		default:
			return fmt.Errorf("unknown ramp type %s", rampType)
		}

	case chain_selectors.FamilySolana:
		chainState, exists := c.SolChains[chainSelector]
		if !exists {
			return fmt.Errorf("chain %d does not exist", chainSelector)
		}
		switch rampType {
		case ccipshared.OffRamp:
			if chainState.OffRamp.IsZero() {
				return fmt.Errorf("offramp contract does not exist on solana chain %d", chainSelector)
			}
		case ccipshared.OnRamp:
			if chainState.Router.IsZero() {
				return fmt.Errorf("router contract does not exist on solana chain %d", chainSelector)
			}
		default:
			return fmt.Errorf("unknown ramp type %s", rampType)
		}

	case chain_selectors.FamilyAptos:
		chainState, exists := c.AptosChains[chainSelector]
		if !exists {
			return fmt.Errorf("chain %d does not exist", chainSelector)
		}
		if chainState.CCIPAddress == (aptos.AccountAddress{}) {
			return fmt.Errorf("ccip package does not exist on aptos chain %d", chainSelector)
		}

	case chain_selectors.FamilyTon:
		chainState, exists := c.TonChains[chainSelector]
		if !exists {
			return fmt.Errorf("chain %d does not exist", chainSelector)
		}
		switch rampType {
		case ccipshared.OnRamp:
			if chainState.Router.IsAddrNone() {
				return fmt.Errorf("router contract does not exist on ton chain %d", chainSelector)
			}
		case ccipshared.OffRamp:
			if chainState.OffRamp.IsAddrNone() {
				return fmt.Errorf("offramp contract does not exist on ton chain %d", chainSelector)
			}
		default:
			return fmt.Errorf("unknown ramp type %s", rampType)
		}

	default:
		return fmt.Errorf("unknown chain family %s", family)
	}
	return nil
}

func (c CCIPOnChainState) GetEVMChainState(env cldf.Environment, chainSelector uint64) (cldf_evm.Chain, evm.CCIPChainState, error) {
	err := cldf.IsValidChainSelector(chainSelector)
	if err != nil {
		return cldf_evm.Chain{}, evm.CCIPChainState{}, fmt.Errorf("failed to validate chain selector %d: %w", chainSelector, err)
	}
	chain, ok := env.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return cldf_evm.Chain{}, evm.CCIPChainState{}, fmt.Errorf("chain with selector %d does not exist in environment", chainSelector)
	}
	chainState, ok := c.Chains[chainSelector]
	if !ok {
		return cldf_evm.Chain{}, evm.CCIPChainState{}, fmt.Errorf("chain with selector %d does not exist in state", chainSelector)
	}
	if chainState.RMNProxy == nil {
		return cldf_evm.Chain{}, evm.CCIPChainState{}, fmt.Errorf("missing rmnProxy on %s", chain)
	}

	return chain, chainState, nil
}

func (c CCIPOnChainState) UpdateMCMSStateWithAddressFromDatastoreForChain(e cldf.Environment, selector uint64, qualifier string) error {
	mcmsStateWithQualifier, err := commonstate.MaybeLoadMCMSWithTimelockStateDataStoreWithQualifier(e, []uint64{selector}, qualifier)
	if err != nil {
		return fmt.Errorf("failed to load mcms state from datastore with qualifier %s: %w", qualifier, err)
	}
	for chainSelector, mcmsState := range mcmsStateWithQualifier {
		if chainState, ok := c.EVMChainState(chainSelector); ok {
			chainState.MCMSWithTimelockState = *mcmsState
			chainState.ABIByAddress[mcmsState.ProposerMcm.Address().Hex()] = gethwrappers.ManyChainMultiSigABI
			chainState.ABIByAddress[mcmsState.CancellerMcm.Address().Hex()] = gethwrappers.ManyChainMultiSigABI
			chainState.ABIByAddress[mcmsState.BypasserMcm.Address().Hex()] = gethwrappers.ManyChainMultiSigABI
			chainState.ABIByAddress[mcmsState.Timelock.Address().Hex()] = gethwrappers.RBACTimelockABI
			chainState.ABIByAddress[mcmsState.CallProxy.Address().Hex()] = gethwrappers.CallProxyABI
			// write back to state
			c.WriteEVMChainState(chainSelector, chainState)
		}
	}
	return nil
}

type LoadOption func(*loadStateOpts)

type loadStateOpts struct {
	loadLegacyContracts bool
}

func WithLoadLegacyContracts(load bool) LoadOption {
	return func(c *loadStateOpts) {
		c.loadLegacyContracts = load
	}
}

func LoadOnchainState(e cldf.Environment, opts ...LoadOption) (CCIPOnChainState, error) {
	solanaState, err := LoadOnchainStateSolana(e)
	if err != nil {
		return CCIPOnChainState{}, err
	}
	aptosChains, err := aptosstate.LoadOnchainStateAptos(e)
	if err != nil {
		return CCIPOnChainState{}, err
	}
	tonChains, err := tonstate.LoadOnchainState(e)
	if err != nil {
		return CCIPOnChainState{}, err
	}

	state := CCIPOnChainState{
		Chains:      make(map[uint64]evm.CCIPChainState),
		SolChains:   solanaState.SolChains,
		AptosChains: aptosChains,
		TonChains:   tonChains,
		evmMu:       &sync.RWMutex{},
	}
	for chainSelector, chain := range e.BlockChains.EVMChains() {
		// get all addresses for chain from addressbook
		// here we do not load addresses from datastore as there can be multiple
		// contracts of the same type and version in datastore which can lead to
		// ambiguity while loading the state
		addresses, err := e.ExistingAddresses.AddressesForChain(chainSelector)
		if err != nil && !errors.Is(err, cldf.ErrChainNotFound) {
			return state, fmt.Errorf("failed to get addresses for chain %d: %w", chainSelector, err)
		}
		chainState, err := LoadChainState(e.GetContext(), chain, addresses, opts...)
		if err != nil {
			return state, err
		}
		state.WriteEVMChainState(chainSelector, chainState)
	}
	return state, state.Validate()
}

// LoadChainState Loads all state for a chain into state
func LoadChainState(ctx context.Context, chain cldf_evm.Chain, addresses map[string]cldf.TypeAndVersion, opts ...LoadOption) (evm.CCIPChainState, error) {
	config := &loadStateOpts{}
	for _, opt := range opts {
		opt(config)
	}

	var state evm.CCIPChainState
	mcmsWithTimelock, err := commonstate.MaybeLoadMCMSWithTimelockChainState(chain, addresses)
	if err != nil {
		return state, err
	}
	state.MCMSWithTimelockState = *mcmsWithTimelock

	linkState, err := commonstate.MaybeLoadLinkTokenChainState(chain, addresses)
	if err != nil {
		return state, err
	}
	state.LinkTokenState = *linkState
	staticLinkState, err := commonstate.MaybeLoadStaticLinkTokenState(chain, addresses)
	if err != nil {
		return state, err
	}
	state.StaticLinkTokenState = *staticLinkState
	state.ABIByAddress = make(map[string]string)
	for address, tvStr := range addresses {
		switch tvStr.String() {
		case cldf.NewTypeAndVersion(commontypes.RBACTimelock, deployment.Version1_0_0).String():
			state.ABIByAddress[address] = gethwrappers.RBACTimelockABI
		case cldf.NewTypeAndVersion(commontypes.CallProxy, deployment.Version1_0_0).String():
			state.ABIByAddress[address] = gethwrappers.CallProxyABI
		case cldf.NewTypeAndVersion(commontypes.ProposerManyChainMultisig, deployment.Version1_0_0).String(),
			cldf.NewTypeAndVersion(commontypes.CancellerManyChainMultisig, deployment.Version1_0_0).String(),
			cldf.NewTypeAndVersion(commontypes.BypasserManyChainMultisig, deployment.Version1_0_0).String():
			state.ABIByAddress[address] = gethwrappers.ManyChainMultiSigABI
		case cldf.NewTypeAndVersion(commontypes.LinkToken, deployment.Version1_0_0).String():
			state.ABIByAddress[address] = link_token.LinkTokenABI
		case cldf.NewTypeAndVersion(commontypes.StaticLinkToken, deployment.Version1_0_0).String():
			state.ABIByAddress[address] = link_token_interface.LinkTokenABI
		case cldf.NewTypeAndVersion(ccipshared.CapabilitiesRegistry, deployment.Version1_0_0).String():
			cr, err := capabilities_registry.NewCapabilitiesRegistry(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.CapabilityRegistry = cr
			state.ABIByAddress[address] = capabilities_registry.CapabilitiesRegistryABI
		case cldf.NewTypeAndVersion(ccipshared.OnRamp, deployment.Version1_6_0).String():
			onRampC, err := onramp.NewOnRamp(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.OnRamp = onRampC
			state.ABIByAddress[address] = onramp.OnRampABI
		case cldf.NewTypeAndVersion(ccipshared.OffRamp, deployment.Version1_6_0).String():
			offRamp, err := offramp.NewOffRamp(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.OffRamp = offRamp
			state.ABIByAddress[address] = offramp.OffRampABI
		case cldf.NewTypeAndVersion(ccipshared.ARMProxy, deployment.Version1_0_0).String():
			armProxy, err := rmn_proxy_contract.NewRMNProxy(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RMNProxy = armProxy
			state.ABIByAddress[address] = rmn_proxy_contract.RMNProxyABI
		case cldf.NewTypeAndVersion(ccipshared.RMNRemote, deployment.Version1_6_0).String():
			rmnRemote, err := rmn_remote.NewRMNRemote(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RMNRemote = rmnRemote
			state.ABIByAddress[address] = rmn_remote.RMNRemoteABI
		case cldf.NewTypeAndVersion(ccipshared.RMNHome, deployment.Version1_6_0).String():
			rmnHome, err := rmn_home.NewRMNHome(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RMNHome = rmnHome
			state.ABIByAddress[address] = rmn_home.RMNHomeABI
		case cldf.NewTypeAndVersion(ccipshared.WETH9, deployment.Version1_0_0).String():
			_weth9, err := weth9.NewWETH9(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.Weth9 = _weth9
			state.ABIByAddress[address] = weth9.WETH9ABI
		case cldf.NewTypeAndVersion(ccipshared.NonceManager, deployment.Version1_6_0).String():
			nm, err := nonce_manager.NewNonceManager(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.NonceManager = nm
			state.ABIByAddress[address] = nonce_manager.NonceManagerABI
		case cldf.NewTypeAndVersion(ccipshared.TokenAdminRegistry, deployment.Version1_5_0).String():
			tm, err := token_admin_registry.NewTokenAdminRegistry(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.TokenAdminRegistry = tm
			state.ABIByAddress[address] = token_admin_registry.TokenAdminRegistryABI
		case cldf.NewTypeAndVersion(ccipshared.TokenPoolFactory, deployment.Version1_5_1).String():
			tpf, err := token_pool_factory.NewTokenPoolFactory(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.TokenPoolFactory = tpf
			state.ABIByAddress[address] = token_pool_factory.TokenPoolFactoryABI
		case cldf.NewTypeAndVersion(ccipshared.RegistryModule, deployment.Version1_6_0).String():
			rm, err := registryModuleOwnerCustomv16.NewRegistryModuleOwnerCustom(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RegistryModules1_6 = append(state.RegistryModules1_6, rm)
			state.ABIByAddress[address] = registryModuleOwnerCustomv16.RegistryModuleOwnerCustomABI
		case cldf.NewTypeAndVersion(ccipshared.RegistryModule, deployment.Version1_5_0).String():
			rm, err := registryModuleOwnerCustomv15.NewRegistryModuleOwnerCustom(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RegistryModules1_5 = append(state.RegistryModules1_5, rm)
			state.ABIByAddress[address] = registryModuleOwnerCustomv15.RegistryModuleOwnerCustomABI
		case cldf.NewTypeAndVersion(ccipshared.Router, deployment.Version1_2_0).String():
			r, err := router.NewRouter(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.Router = r
			state.ABIByAddress[address] = router.RouterABI
		case cldf.NewTypeAndVersion(ccipshared.TestRouter, deployment.Version1_2_0).String():
			r, err := router.NewRouter(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.TestRouter = r
			state.ABIByAddress[address] = router.RouterABI
		case cldf.NewTypeAndVersion(ccipshared.USDCToken, deployment.Version1_0_0).String():
			ut, err := burn_mint_erc677.NewBurnMintERC677(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.BurnMintTokens677 = map[ccipshared.TokenSymbol]*burn_mint_erc677.BurnMintERC677{
				ccipshared.USDCSymbol: ut,
			}
			state.ABIByAddress[address] = burn_mint_erc677.BurnMintERC677ABI
		case cldf.NewTypeAndVersion(ccipshared.CCTPMessageTransmitterProxy, deployment.Version1_6_2).String():
			cmtp, err := cctp_message_transmitter_proxy.NewCCTPMessageTransmitterProxy(
				common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.CCTPMessageTransmitterProxies == nil {
				state.CCTPMessageTransmitterProxies = make(map[semver.Version]*cctp_message_transmitter_proxy.CCTPMessageTransmitterProxy)
			}
			state.CCTPMessageTransmitterProxies[deployment.Version1_6_2] = cmtp
			state.ABIByAddress[address] = cctp_message_transmitter_proxy.CCTPMessageTransmitterProxyABI
		case cldf.NewTypeAndVersion(ccipshared.USDCTokenPool, deployment.Version1_5_1).String():
			utp, err := usdc_token_pool.NewUSDCTokenPool(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.USDCTokenPools == nil {
				state.USDCTokenPools = make(map[semver.Version]*usdc_token_pool.USDCTokenPool)
			}
			state.USDCTokenPools[deployment.Version1_5_1] = utp
			state.ABIByAddress[address] = usdc_token_pool.USDCTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.USDCTokenPool, deployment.Version1_6_2).String():
			utp, err := usdc_token_pool_v1_6_2.NewUSDCTokenPool(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.USDCTokenPoolsV1_6 == nil {
				state.USDCTokenPoolsV1_6 = make(map[semver.Version]*usdc_token_pool_v1_6_2.USDCTokenPool)
			}
			state.USDCTokenPoolsV1_6[deployment.Version1_6_2] = utp
		case cldf.NewTypeAndVersion(ccipshared.HybridLockReleaseUSDCTokenPool, deployment.Version1_5_1).String():
			utp, err := usdc_token_pool.NewUSDCTokenPool(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.USDCTokenPools == nil {
				state.USDCTokenPools = make(map[semver.Version]*usdc_token_pool.USDCTokenPool)
			}
			state.USDCTokenPools[deployment.Version1_5_1] = utp
			state.ABIByAddress[address] = usdc_token_pool.USDCTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.HybridLockReleaseUSDCTokenPool, deployment.Version1_6_2).String():
			utp, err := usdc_token_pool_v1_6_2.NewUSDCTokenPool(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.USDCTokenPoolsV1_6 == nil {
				state.USDCTokenPoolsV1_6 = make(map[semver.Version]*usdc_token_pool_v1_6_2.USDCTokenPool)
			}
			state.USDCTokenPoolsV1_6[deployment.Version1_6_2] = utp
			state.ABIByAddress[address] = usdc_token_pool_v1_6_2.USDCTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.USDCMockTransmitter, deployment.Version1_0_0).String():
			umt, err := mock_usdc_token_transmitter.NewMockE2EUSDCTransmitter(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.MockUSDCTransmitter = umt
			state.ABIByAddress[address] = mock_usdc_token_transmitter.MockE2EUSDCTransmitterABI
		case cldf.NewTypeAndVersion(ccipshared.USDCTokenMessenger, deployment.Version1_0_0).String():
			utm, err := mock_usdc_token_messenger.NewMockE2EUSDCTokenMessenger(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.MockUSDCTokenMessenger = utm
			state.ABIByAddress[address] = mock_usdc_token_messenger.MockE2EUSDCTokenMessengerABI
		case cldf.NewTypeAndVersion(ccipshared.CCIPHome, deployment.Version1_6_0).String():
			ccipHome, err := ccip_home.NewCCIPHome(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.CCIPHome = ccipHome
			state.ABIByAddress[address] = ccip_home.CCIPHomeABI
		case cldf.NewTypeAndVersion(ccipshared.CCIPReceiver, deployment.Version1_0_0).String():
			mr, err := maybe_revert_message_receiver.NewMaybeRevertMessageReceiver(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.Receiver = mr
			state.ABIByAddress[address] = maybe_revert_message_receiver.MaybeRevertMessageReceiverABI
		case cldf.NewTypeAndVersion(ccipshared.LogMessageDataReceiver, deployment.Version1_0_0).String():
			mr, err := log_message_data_receiver.NewLogMessageDataReceiver(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.LogMessageDataReceiver = mr
			state.ABIByAddress[address] = log_message_data_receiver.LogMessageDataReceiverABI
		case cldf.NewTypeAndVersion(ccipshared.Multicall3, deployment.Version1_0_0).String():
			mc, err := multicall3.NewMulticall3(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.Multicall3 = mc
			state.ABIByAddress[address] = multicall3.Multicall3ABI
		case cldf.NewTypeAndVersion(ccipshared.PriceFeed, deployment.Version1_0_0).String():
			feed, err := aggregator_v3_interface.NewAggregatorV3Interface(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.USDFeeds == nil {
				state.USDFeeds = make(map[ccipshared.TokenSymbol]*aggregator_v3_interface.AggregatorV3Interface)
			}
			desc, err := feed.Description(&bind.CallOpts{})
			if err != nil {
				return state, err
			}
			keys, ok := ccipshared.GetSymbolsFromDescription(desc)
			if !ok {
				return state, fmt.Errorf("unknown feed description %s", desc)
			}
			for _, key := range keys {
				state.USDFeeds[key] = feed
			}
			state.ABIByAddress[address] = aggregator_v3_interface.AggregatorV3InterfaceABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintTokenPool, deployment.Version1_5_1).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, burn_mint_token_pool.NewBurnMintTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnMintTokenPools = helpers.AddValueToNestedMap(state.BurnMintTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = burn_mint_token_pool.BurnMintTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintFastTransferTokenPool, deployment.Version1_6_1).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, fast_transfer_token_pool.NewBurnMintFastTransferTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnMintFastTransferTokenPools = helpers.AddValueToNestedMap(state.BurnMintFastTransferTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = fast_transfer_token_pool.BurnMintFastTransferTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintFastTransferTokenPool, deployment.Version1_6_3Dev).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, fast_transfer_token_pool.NewBurnMintFastTransferTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnMintFastTransferTokenPools = helpers.AddValueToNestedMap(state.BurnMintFastTransferTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = fast_transfer_token_pool.BurnMintFastTransferTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintWithExternalMinterFastTransferTokenPool, deployment.Version1_6_0).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, burn_mint_with_external_minter_fast_transfer_token_pool.NewBurnMintWithExternalMinterFastTransferTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnMintWithExternalMinterFastTransferTokenPools = helpers.AddValueToNestedMap(state.BurnMintWithExternalMinterFastTransferTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = burn_mint_with_external_minter_fast_transfer_token_pool.BurnMintWithExternalMinterFastTransferTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.HybridWithExternalMinterFastTransferTokenPool, deployment.Version1_6_0).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, hybrid_with_external_minter_fast_transfer_token_pool.NewHybridWithExternalMinterFastTransferTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.HybridWithExternalMinterFastTransferTokenPools = helpers.AddValueToNestedMap(state.HybridWithExternalMinterFastTransferTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = hybrid_with_external_minter_fast_transfer_token_pool.HybridWithExternalMinterFastTransferTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnWithFromMintTokenPool, deployment.Version1_5_1).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, burn_with_from_mint_token_pool.NewBurnWithFromMintTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnWithFromMintTokenPools = helpers.AddValueToNestedMap(state.BurnWithFromMintTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = burn_with_from_mint_token_pool.BurnWithFromMintTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnFromMintTokenPool, deployment.Version1_5_1).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, burn_from_mint_token_pool.NewBurnFromMintTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.BurnFromMintTokenPools = helpers.AddValueToNestedMap(state.BurnFromMintTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = burn_from_mint_token_pool.BurnFromMintTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.LockReleaseTokenPool, deployment.Version1_5_1).String():
			ethAddress := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, lock_release_token_pool.NewLockReleaseTokenPool, ethAddress, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", ethAddress, err)
			}
			state.LockReleaseTokenPools = helpers.AddValueToNestedMap(state.LockReleaseTokenPools, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = lock_release_token_pool.LockReleaseTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintToken, deployment.Version1_0_0).String():
			tok, err := burn_mint_erc677.NewBurnMintERC677(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.BurnMintTokens677 == nil {
				state.BurnMintTokens677 = make(map[ccipshared.TokenSymbol]*burn_mint_erc677.BurnMintERC677)
			}
			symbol, err := tok.Symbol(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.BurnMintTokens677[ccipshared.TokenSymbol(symbol)] = tok
			state.ABIByAddress[address] = burn_mint_erc677.BurnMintERC677ABI
		case cldf.NewTypeAndVersion(ccipshared.ERC20Token, deployment.Version1_0_0).String():
			tok, err := erc20.NewERC20(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.ERC20Tokens == nil {
				state.ERC20Tokens = make(map[ccipshared.TokenSymbol]*erc20.ERC20)
			}
			symbol, err := tok.Symbol(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.ERC20Tokens[ccipshared.TokenSymbol(symbol)] = tok
			state.ABIByAddress[address] = erc20.ERC20ABI
		case cldf.NewTypeAndVersion(ccipshared.FactoryBurnMintERC20Token, deployment.Version1_0_0).String():
			tok, err := factory_burn_mint_erc20.NewFactoryBurnMintERC20(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.FactoryBurnMintERC20Token = tok
			state.ABIByAddress[address] = factory_burn_mint_erc20.FactoryBurnMintERC20ABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintERC20Token, deployment.Version1_0_0).String():
			tok, err := burn_mint_erc20.NewBurnMintERC20(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.BurnMintERC20 == nil {
				state.BurnMintERC20 = make(map[ccipshared.TokenSymbol]*burn_mint_erc20.BurnMintERC20)
			}
			symbol, err := tok.Symbol(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.BurnMintERC20[ccipshared.TokenSymbol(symbol)] = tok
			state.ABIByAddress[address] = burn_mint_erc20.BurnMintERC20ABI
		case cldf.NewTypeAndVersion(ccipshared.ERC677Token, deployment.Version1_0_0).String():
			tok, err := erc677.NewERC677(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.ERC677Tokens == nil {
				state.ERC677Tokens = make(map[ccipshared.TokenSymbol]*erc677.ERC677)
			}
			symbol, err := tok.Symbol(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.ERC677Tokens[ccipshared.TokenSymbol(symbol)] = tok
			state.ABIByAddress[address] = erc677.ERC677ABI
		// legacy addresses below are commented out to avoid loading them by default, to be uncommented for migrations
		case cldf.NewTypeAndVersion(ccipshared.OnRamp, deployment.Version1_5_0).String():
			if !config.loadLegacyContracts {
				continue
			}
			onRampC, err := evm_2_evm_onramp.NewEVM2EVMOnRamp(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			sCfg, err := onRampC.GetStaticConfig(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get static config chain %s: %w", chain.String(), err)
			}
			if state.EVM2EVMOnRamp == nil {
				state.EVM2EVMOnRamp = make(map[uint64]*evm_2_evm_onramp.EVM2EVMOnRamp)
			}
			state.EVM2EVMOnRamp[sCfg.DestChainSelector] = onRampC
			state.ABIByAddress[address] = evm_2_evm_onramp.EVM2EVMOnRampABI
		case cldf.NewTypeAndVersion(ccipshared.OffRamp, deployment.Version1_5_0).String():
			if !config.loadLegacyContracts {
				continue
			}
			offRamp, err := evm_2_evm_offramp.NewEVM2EVMOffRamp(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			sCfg, err := offRamp.GetStaticConfig(nil)
			if err != nil {
				return state, err
			}
			if state.EVM2EVMOffRamp == nil {
				state.EVM2EVMOffRamp = make(map[uint64]*evm_2_evm_offramp.EVM2EVMOffRamp)
			}
			state.EVM2EVMOffRamp[sCfg.SourceChainSelector] = offRamp
			state.ABIByAddress[address] = evm_2_evm_offramp.EVM2EVMOffRampABI
		case cldf.NewTypeAndVersion(ccipshared.CommitStore, deployment.Version1_5_0).String():
			if !config.loadLegacyContracts {
				continue
			}
			commitStore, err := commit_store.NewCommitStore(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			sCfg, err := commitStore.GetStaticConfig(nil)
			if err != nil {
				return state, err
			}
			if state.CommitStore == nil {
				state.CommitStore = make(map[uint64]*commit_store.CommitStore)
			}
			state.CommitStore[sCfg.SourceChainSelector] = commitStore
			state.ABIByAddress[address] = commit_store.CommitStoreABI
		case cldf.NewTypeAndVersion(ccipshared.PriceRegistry, deployment.Version1_2_0).String():
			if !config.loadLegacyContracts {
				continue
			}
			pr, err := price_registry_1_2_0.NewPriceRegistry(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.PriceRegistry = pr
			state.ABIByAddress[address] = price_registry_1_2_0.PriceRegistryABI
		case cldf.NewTypeAndVersion(ccipshared.RMN, deployment.Version1_5_0).String():
			if !config.loadLegacyContracts {
				continue
			}
			rmnC, err := rmn_contract.NewRMNContract(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.RMN = rmnC
			state.ABIByAddress[address] = rmn_contract.RMNContractABI
		case cldf.NewTypeAndVersion(ccipshared.MockRMN, deployment.Version1_0_0).String():
			mockRMN, err := mock_rmn_contract.NewMockRMNContract(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.MockRMN = mockRMN
			state.ABIByAddress[address] = mock_rmn_contract.MockRMNContractABI
		case cldf.NewTypeAndVersion(ccipshared.FeeAggregator, deployment.Version1_0_0).String():
			state.FeeAggregator = common.HexToAddress(address)
		case cldf.NewTypeAndVersion(ccipshared.FiredrillEntrypointType, deployment.Version1_5_0).String(),
			cldf.NewTypeAndVersion(ccipshared.FiredrillEntrypointType, deployment.Version1_6_0).String():
			// Ignore firedrill contracts
			// Firedrill contracts are unknown to core and their state is being loaded separately
		case cldf.NewTypeAndVersion(ccipshared.DonIDClaimer, deployment.Version1_6_1).String():
			donIDClaimer, err := don_id_claimer.NewDonIDClaimer(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			state.DonIDClaimer = donIDClaimer
			state.ABIByAddress[address] = don_id_claimer.DonIDClaimerABI
		case cldf.NewTypeAndVersion(ccipshared.ERC677TokenHelper, deployment.Version1_0_0).String():
			ERC677HelperToken, err := burn_mint_erc20_with_drip.NewBurnMintERC20(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}

			if state.BurnMintERC20WithDrip == nil {
				state.BurnMintERC20WithDrip = make(map[ccipshared.TokenSymbol]*burn_mint_erc20_with_drip.BurnMintERC20)
			}
			symbol, err := ERC677HelperToken.Symbol(nil)
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.BurnMintERC20WithDrip[ccipshared.TokenSymbol(symbol)] = ERC677HelperToken
			state.ABIByAddress[address] = burn_mint_erc20_with_drip.BurnMintERC20ABI
		case cldf.NewTypeAndVersion(ccipshared.BurnMintWithExternalMinterTokenPool, deployment.Version1_6_0).String():
			addr := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, burn_mint_with_external_minter_token_pool.NewBurnMintWithExternalMinterTokenPool, addr, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", addr, err)
			}
			state.BurnMintWithExternalMinterTokenPool = helpers.AddValueToNestedMap(state.BurnMintWithExternalMinterTokenPool, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = burn_mint_with_external_minter_token_pool.BurnMintWithExternalMinterTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.HybridWithExternalMinterTokenPool, deployment.Version1_6_0).String():
			addr := common.HexToAddress(address)
			pool, metadata, err := ccipshared.NewTokenPoolWithMetadata(ctx, hybrid_with_external_minter_token_pool.NewHybridWithExternalMinterTokenPool, addr, chain.Client)
			if err != nil {
				return state, fmt.Errorf("failed to connect address %s with token pool bindings and get token symbol: %w", addr, err)
			}
			state.HybridWithExternalMinterTokenPool = helpers.AddValueToNestedMap(state.HybridWithExternalMinterTokenPool, metadata.Symbol, metadata.Version, pool)
			state.ABIByAddress[address] = hybrid_with_external_minter_token_pool.HybridWithExternalMinterTokenPoolABI
		case cldf.NewTypeAndVersion(ccipshared.TokenGovernor, deployment.Version1_6_0).String():
			tokenGovernor, err := token_governor.NewTokenGovernor(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}
			if state.TokenGovernor == nil {
				state.TokenGovernor = make(map[ccipshared.TokenSymbol]*token_governor.TokenGovernor)
			}
			tokenAddress, err := tokenGovernor.GetToken(&bind.CallOpts{Context: ctx})
			if err != nil {
				return state, fmt.Errorf("failed to get token address of token governor at %s: %w", address, err)
			}
			token, err := erc20.NewERC20(common.HexToAddress(tokenAddress.String()), chain.Client)
			if err != nil {
				return state, err
			}
			symbol, err := token.Symbol(&bind.CallOpts{Context: ctx})
			if err != nil {
				return state, fmt.Errorf("failed to get token symbol of token at %s: %w", address, err)
			}
			state.TokenGovernor[ccipshared.TokenSymbol(symbol)] = tokenGovernor
			state.ABIByAddress[address] = token_governor.TokenGovernorABI
		case cldf.NewTypeAndVersion(ccipshared.EVMSignerRegistry, deployment.Version1_0_0).String():
			signerRegistry, err := signer_registry.NewSignerRegistry(common.HexToAddress(address), chain.Client)
			if err != nil {
				return state, err
			}

			state.SignerRegistry = signerRegistry
			state.ABIByAddress[address] = signer_registry.SignerRegistryABI
		default:
			// ManyChainMultiSig 1.0.0 can have any of these labels, it can have either 1,2 or 3 of these -
			// bypasser, proposer and canceller
			// if you try to compare tvStr.String() you will have to compare all combinations of labels
			// so we will compare the type and version only
			if tvStr.Type == commontypes.ManyChainMultisig && tvStr.Version == deployment.Version1_0_0 {
				state.ABIByAddress[address] = gethwrappers.ManyChainMultiSigABI
				continue
			}
			// New versions of the EVM FeeQuoter are developed to support new chain families.
			// The FeeQuoter added to state should be the FeeQuoter in the environment with the highest version.
			if tvStr.Type == ccipshared.FeeQuoter {
				if state.FeeQuoter == nil || tvStr.Version.GreaterThan(state.FeeQuoterVersion) {
					fq, err := fee_quoter.NewFeeQuoter(common.HexToAddress(address), chain.Client)
					if err != nil {
						return state, err
					}
					state.FeeQuoter = fq
					state.FeeQuoterVersion = &tvStr.Version
					state.ABIByAddress[address] = fee_quoter.FeeQuoterABI
				}
				continue
			}
			return state, fmt.Errorf("unknown contract %s", tvStr)
		}
	}
	return state, nil
}

func ValidateChain(env cldf.Environment, state CCIPOnChainState, chainSel uint64, mcmsCfg *proposalutils.TimelockConfig) error {
	err := cldf.IsValidChainSelector(chainSel)
	if err != nil {
		return fmt.Errorf("is not valid chain selector %d: %w", chainSel, err)
	}
	family, err := chain_selectors.GetSelectorFamily(chainSel)
	if err != nil {
		return fmt.Errorf("failed to find family for chain selector %d: %w", chainSel, err)
	}
	switch family {
	case chain_selectors.FamilyEVM:
		chain, ok := env.BlockChains.EVMChains()[chainSel]
		if !ok {
			return fmt.Errorf("evm chain with selector %d does not exist in environment", chainSel)
		}
		chainState, ok := state.EVMChainState(chainSel)
		if !ok {
			return fmt.Errorf("%s does not exist in state", chain)
		}
		if mcmsCfg != nil {
			err = mcmsCfg.Validate(chain, commonstate.MCMSWithTimelockState{
				CancellerMcm: chainState.CancellerMcm,
				ProposerMcm:  chainState.ProposerMcm,
				BypasserMcm:  chainState.BypasserMcm,
				Timelock:     chainState.Timelock,
				CallProxy:    chainState.CallProxy,
			})
			if err != nil {
				return err
			}
		}
	case chain_selectors.FamilySolana:
		chain, ok := env.BlockChains.SolanaChains()[chainSel]
		if !ok {
			return fmt.Errorf("solana chain with selector %d does not exist in environment", chainSel)
		}
		_, ok = state.SolChains[chainSel]
		if !ok {
			return fmt.Errorf("%s does not exist in state", chain)
		}
		if mcmsCfg != nil {
			err = mcmsCfg.ValidateSolana(env, chainSel)
			if err != nil {
				return err
			}
		}
	case chain_selectors.FamilyAptos:
		chain, ok := env.BlockChains.AptosChains()[chainSel]
		if !ok {
			return fmt.Errorf("aptos chain with selector %d does not exist in environment", chainSel)
		}
		s, ok := state.AptosChains[chainSel]
		if !ok {
			return fmt.Errorf("%s does not exist in state", chain)
		}
		if mcmsCfg != nil {
			if err := mcmsCfg.ValidateAptos(chain, s.MCMSAddress); err != nil {
				return err
			}
		}
	case chain_selectors.FamilyTon:
		chain, ok := env.BlockChains.TonChains()[chainSel]
		if !ok {
			return fmt.Errorf("ton chain with selector %d does not exist in environment", chainSel)
		}
		_, ok = state.TonChains[chainSel]
		if !ok {
			return fmt.Errorf("%s does not exist in state", chain)
		}
		// TODO validate ton mcms after implemented
	default:
		return fmt.Errorf("%s family not support", family)
	}
	return nil
}

func LoadOnchainStateSolana(e cldf.Environment) (CCIPOnChainState, error) {
	state := CCIPOnChainState{
		SolChains: make(map[uint64]solana.CCIPChainState),
	}
	for chainSelector, chain := range e.BlockChains.SolanaChains() {
		addresses, err := e.ExistingAddresses.AddressesForChain(chainSelector)
		if err != nil {
			// Chain not found in address book, initialize empty
			if !errors.Is(err, cldf.ErrChainNotFound) {
				return state, err
			}
			addresses = make(map[string]cldf.TypeAndVersion)
		}
		chainState, err := solana.LoadChainStateSolana(chain, addresses)
		if err != nil {
			return state, err
		}
		state.SolChains[chainSelector] = chainState
	}
	return state, nil
}
