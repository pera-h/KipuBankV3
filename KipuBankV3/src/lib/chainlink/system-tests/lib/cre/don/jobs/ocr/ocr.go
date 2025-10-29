package ocr

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	ptypes "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	"github.com/smartcontractkit/chainlink/system-tests/lib/cre"
	crecapabilities "github.com/smartcontractkit/chainlink/system-tests/lib/cre/capabilities"
	standardcapability "github.com/smartcontractkit/chainlink/system-tests/lib/cre/don/jobs/standardcapability"
	"github.com/smartcontractkit/chainlink/v2/core/services/job"
)

func GenerateJobSpecsForStandardCapabilityWithOCR(
	don *cre.Don,
	dons *cre.Dons,
	creEnv *cre.Environment,
	flag cre.CapabilityFlag,
	contractNamer ContractNamer,
	dataStoreOCR3ContractKeyProvider DataStoreOCR3ContractKeyProvider,
	capabilityEnabler CapabilityEnabler,
	enabledChainsProvider EnabledChainsProvider,
	jobConfigGenerator JobConfigGenerator,
	configMerger ConfigMerger,
) ([]*jobv1.ProposeJobRequest, error) {
	if configMerger == nil {
		return nil, errors.New("config merger is nil")
	}
	if jobConfigGenerator == nil {
		return nil, errors.New("job config generator is nil")
	}
	if contractNamer == nil {
		return nil, errors.New("contract namer is nil")
	}
	if capabilityEnabler == nil {
		return nil, errors.New("capability enabler is nil")
	}
	if enabledChainsProvider == nil {
		return nil, errors.New("enabled chains provider is nil")
	}

	jobSpecs := []*jobv1.ProposeJobRequest{}
	logger := framework.L

	if !capabilityEnabler(don, flag) {
		return jobSpecs, nil
	}

	capabilityConfig, ok := creEnv.CapabilityConfigs[flag]
	if !ok {
		return nil, fmt.Errorf("%s config not found in capabilities config: %v", flag, creEnv.CapabilityConfigs)
	}

	containerPath, pathErr := crecapabilities.DefaultContainerDirectory(creEnv.Provider.Type)
	if pathErr != nil {
		return nil, errors.Wrapf(pathErr, "failed to get default container directory for infra type %s", creEnv.Provider.Type)
	}

	binaryPath := filepath.Join(containerPath, filepath.Base(capabilityConfig.BinaryPath))

	workerNodes, wErr := don.Workers()
	if wErr != nil {
		return nil, errors.Wrap(wErr, "failed to find worker nodes")
	}

	bootstrapNode, isBootstrap := dons.Bootstrap()
	if !isBootstrap {
		return nil, errors.New("could not find bootstrap node in topology, exactly one bootstrap node is required")
	}

	var nodeSet cre.NodeSetWithCapabilityConfigs
	for _, ns := range dons.AsNodeSetWithChainCapabilities() {
		if ns.GetName() == don.Name {
			nodeSet = ns
			break
		}
	}
	if nodeSet == nil {
		return nil, fmt.Errorf("could not find node set for Don named '%s'", don.Name)
	}

	chainIDs, err := enabledChainsProvider(creEnv.RegistryChainSelector, nodeSet, flag)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled chains %w", err)
	}

	for _, chainID := range chainIDs {
		chainIDStr := strconv.FormatUint(chainID, 10)
		chain, ok := chainsel.ChainByEvmChainID(chainID)
		if !ok {
			return nil, fmt.Errorf("failed to get chain selector for chain ID %d", chainID)
		}

		mergedConfig, enabled, rErr := configMerger(flag, nodeSet, chainID, capabilityConfig)
		if rErr != nil {
			return nil, errors.Wrap(rErr, "failed to merge capability config")
		}

		// if the capability is not enabled for this chain, skip
		if !enabled {
			continue
		}

		cs, ok := chainsel.EvmChainIdToChainSelector()[chainID]
		if !ok {
			return nil, fmt.Errorf("chain selector not found for chainID: %d", chainID)
		}

		contractName := contractNamer(chainID)
		ocr3Key := dataStoreOCR3ContractKeyProvider(contractName, cs)
		ocr3ConfigContractAddress, err := creEnv.CldfEnvironment.DataStore.Addresses().Get(ocr3Key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed contract address for key %s and chainID %d", ocr3Key, chainID)
		}

		// create job specs for the bootstrap node
		jobSpecs = append(jobSpecs, BootstrapOCR3(bootstrapNode.JobDistributorDetails.NodeID, contractName, ocr3ConfigContractAddress.Address, chainID))
		logger.Debug().Msgf("Found deployed '%s' OCR3 contract on chain %d at %s", contractName, chainID, ocr3ConfigContractAddress.Address)

		for _, workerNode := range workerNodes {
			evmKey, ok := workerNode.Keys.EVM[chainID]
			if !ok {
				return nil, fmt.Errorf("failed to get EVM key (chainID %d, node index %d)", chainID, workerNode.Index)
			}
			transmitterAddress := evmKey.PublicAddress.Hex()

			evmKeyBundle, ok := workerNode.Keys.OCR2BundleIDs[chainsel.FamilyEVM] // we can always expect evm bundle key id present since evm is the registry chain
			if !ok {
				return nil, errors.New("failed to get key bundle id for evm family")
			}

			nodeAddress := transmitterAddress
			logger.Debug().Msgf("Deployed node on chain %d/%d at %s", chainID, chain.Selector, nodeAddress)

			bootstrapPeers := []string{fmt.Sprintf("%s@%s:%d", strings.TrimPrefix(bootstrapNode.Keys.PeerID(), "p2p_"), bootstrapNode.Host, cre.OCRPeeringPort)}

			strategyName := "single-chain"
			if len(workerNode.Keys.OCR2BundleIDs) > 1 {
				strategyName = "multi-chain"
			}

			oracleFactoryConfigInstance := job.OracleFactoryConfig{
				Enabled:            true,
				ChainID:            chainIDStr,
				BootstrapPeers:     bootstrapPeers,
				OCRContractAddress: ocr3ConfigContractAddress.Address,
				OCRKeyBundleID:     evmKeyBundle,
				TransmitterID:      transmitterAddress,
				OnchainSigning: job.OnchainSigningStrategy{
					StrategyName: strategyName,
					Config:       workerNode.Keys.OCR2BundleIDs,
				},
			}

			// TODO: merge with jobConfig?
			type OracleFactoryConfigWrapper struct {
				OracleFactory job.OracleFactoryConfig `toml:"oracle_factory"`
			}
			wrapper := OracleFactoryConfigWrapper{OracleFactory: oracleFactoryConfigInstance}

			var oracleBuffer bytes.Buffer
			if errEncoder := toml.NewEncoder(&oracleBuffer).Encode(wrapper); errEncoder != nil {
				return nil, errors.Wrap(errEncoder, "failed to encode oracle factory config to TOML")
			}
			oracleStr := strings.ReplaceAll(oracleBuffer.String(), "\n", "\n\t")

			logger.Debug().Msgf("Creating %s Capability job spec for chainID: %d, selector: %d, DON: %q, node: %q", flag, chainID, chain.Selector, don.Name, workerNode.Name)

			jobConfig, cErr := jobConfigGenerator(logger, chainID, nodeAddress, mergedConfig)
			if cErr != nil {
				return nil, errors.Wrap(cErr, "failed to generate job config")
			}

			jobName := contractName
			if chainID != 0 {
				jobName = jobName + "-" + strconv.FormatUint(chainID, 10)
			}

			jobSpec := standardcapability.WorkerJobSpec(workerNode.JobDistributorDetails.NodeID, jobName, binaryPath, jobConfig, oracleStr)
			jobSpec.Labels = []*ptypes.Label{{Key: cre.CapabilityLabelKey, Value: &flag}}
			jobSpecs = append(jobSpecs, jobSpec)
		}
	}

	return jobSpecs, nil
}

func BootstrapOCR3(nodeID string, name string, ocr3CapabilityAddress string, chainID uint64) *jobv1.ProposeJobRequest {
	uuid := uuid.NewString()

	return &jobv1.ProposeJobRequest{
		NodeId: nodeID,
		Spec: fmt.Sprintf(`
	type = "bootstrap"
	schemaVersion = 1
	externalJobID = "%s"
	name = "%s"
	contractID = "%s"
	contractConfigTrackerPollInterval = "1s"
	contractConfigConfirmations = 1
	relay = "evm"
	[relayConfig]
	chainID = %d
	providerType = "ocr3-capability"
`,
			uuid,
			"ocr3-bootstrap-"+name+fmt.Sprintf("-%d", chainID),
			ocr3CapabilityAddress,
			chainID),
	}
}

// ConfigMerger merges default config with overrides (either on DON or chain level)
type ConfigMerger func(flag cre.CapabilityFlag, nodeSet cre.NodeSetWithCapabilityConfigs, chainIDUint64 uint64, capabilityConfig cre.CapabilityConfig) (map[string]any, bool, error)

// JobConfigGenerator constains the logic that generates the job-specific part of the job spec
type JobConfigGenerator = func(logger zerolog.Logger, chainID uint64, nodeAddress string, mergedConfig map[string]any) (string, error)

// CapabilityEnabler determines if a capability is enabled for a given DON
type CapabilityEnabler func(don *cre.Don, flag cre.CapabilityFlag) bool

// EnabledChainsProvider provides the list of enabled chains for a given capability
type EnabledChainsProvider func(registryChainSelector uint64, nodeSet cre.NodeSetWithCapabilityConfigs, flag cre.CapabilityFlag) ([]uint64, error)

// ContractNamer is a function that returns the name of the OCR3 contract  used in the datastore
type ContractNamer func(chainID uint64) string

type DataStoreOCR3ContractKeyProvider func(contractName string, chainSelector uint64) datastore.AddressRefKey
