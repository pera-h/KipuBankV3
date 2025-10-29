package sequences

import (
	"errors"

	"github.com/Masterminds/semver/v3"
	mcmslib "github.com/smartcontractkit/mcms"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	capabilities_registry_v2 "github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	commonchangeset "github.com/smartcontractkit/chainlink/deployment/common/changeset/state"
	"github.com/smartcontractkit/chainlink/deployment/cre/capabilities_registry/v2/changeset/operations/contracts"
	"github.com/smartcontractkit/chainlink/deployment/cre/ocr3"
)

type ConfigureCapabilitiesRegistryDeps struct {
	Env           *cldf.Environment
	MCMSContracts *commonchangeset.MCMSWithTimelockState // Required if MCMSConfig is not nil
}

type ConfigureCapabilitiesRegistryInput struct {
	RegistryChainSel uint64
	MCMSConfig       *ocr3.MCMSConfig
	Description      string
	ContractAddress  string
	Nops             []capabilities_registry_v2.CapabilitiesRegistryNodeOperatorParams
	Nodes            []capabilities_registry_v2.CapabilitiesRegistryNodeParams
	Capabilities     []capabilities_registry_v2.CapabilitiesRegistryCapability
	DONs             []capabilities_registry_v2.CapabilitiesRegistryNewDONParams
}

func (c ConfigureCapabilitiesRegistryInput) Validate() error {
	if c.ContractAddress == "" {
		return errors.New("ContractAddress is not set")
	}
	return nil
}

type ConfigureCapabilitiesRegistryOutput struct {
	Nops                  []*capabilities_registry_v2.CapabilitiesRegistryNodeOperatorAdded
	Nodes                 []*capabilities_registry_v2.CapabilitiesRegistryNodeAdded
	Capabilities          []*capabilities_registry_v2.CapabilitiesRegistryCapabilityConfigured
	DONs                  []capabilities_registry_v2.CapabilitiesRegistryDONInfo
	MCMSTimelockProposals []mcmslib.TimelockProposal
}

var ConfigureCapabilitiesRegistry = operations.NewSequence(
	"configure-capabilities-registry",
	semver.MustParse("1.0.0"),
	"Configures the capabilities registry by registering node operators, nodes, dons and capabilities",
	func(b operations.Bundle, deps ConfigureCapabilitiesRegistryDeps, input ConfigureCapabilitiesRegistryInput) (ConfigureCapabilitiesRegistryOutput, error) {
		var allProposals []mcmslib.TimelockProposal

		// Register Node Operators
		registerNopsReport, err := operations.ExecuteOperation(b, contracts.RegisterNops, contracts.RegisterNopsDeps{
			Env:           deps.Env,
			MCMSContracts: deps.MCMSContracts,
		}, contracts.RegisterNopsInput{
			ChainSelector: input.RegistryChainSel,
			Address:       input.ContractAddress,
			Nops:          input.Nops,
			MCMSConfig:    input.MCMSConfig,
		})
		if err != nil {
			return ConfigureCapabilitiesRegistryOutput{}, err
		}
		allProposals = append(allProposals, registerNopsReport.Output.Proposals...)

		// Register capabilities
		registerCapabilitiesReport, err := operations.ExecuteOperation(b, contracts.RegisterCapabilities, contracts.RegisterCapabilitiesDeps{
			Env:           deps.Env,
			MCMSContracts: deps.MCMSContracts,
		}, contracts.RegisterCapabilitiesInput{
			ChainSelector: input.RegistryChainSel,
			Address:       input.ContractAddress,
			Capabilities:  input.Capabilities,
			MCMSConfig:    input.MCMSConfig,
		})
		if err != nil {
			return ConfigureCapabilitiesRegistryOutput{}, err
		}
		allProposals = append(allProposals, registerCapabilitiesReport.Output.Proposals...)

		// Register Nodes
		registerNodesReport, err := operations.ExecuteOperation(b, contracts.RegisterNodes, contracts.RegisterNodesDeps{
			Env:           deps.Env,
			MCMSContracts: deps.MCMSContracts,
		}, contracts.RegisterNodesInput{
			ChainSelector: input.RegistryChainSel,
			Address:       input.ContractAddress,
			Nodes:         input.Nodes,
			MCMSConfig:    input.MCMSConfig,
		})
		if err != nil {
			return ConfigureCapabilitiesRegistryOutput{}, err
		}
		allProposals = append(allProposals, registerNodesReport.Output.Proposals...)

		// Register DONs
		registerDONsReport, err := operations.ExecuteOperation(b, contracts.RegisterDons, contracts.RegisterDonsDeps{
			Env:           deps.Env,
			MCMSContracts: deps.MCMSContracts,
		}, contracts.RegisterDonsInput{
			ChainSelector: input.RegistryChainSel,
			Address:       input.ContractAddress,
			DONs:          input.DONs,
			MCMSConfig:    input.MCMSConfig,
		})
		if err != nil {
			return ConfigureCapabilitiesRegistryOutput{}, err
		}
		allProposals = append(allProposals, registerDONsReport.Output.Proposals...)

		return ConfigureCapabilitiesRegistryOutput{
			Nops:                  registerNopsReport.Output.Nops,
			Nodes:                 registerNodesReport.Output.Nodes,
			Capabilities:          registerCapabilitiesReport.Output.Capabilities,
			DONs:                  registerDONsReport.Output.DONs,
			MCMSTimelockProposals: allProposals,
		}, nil
	},
)
