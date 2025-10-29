package aptos

import (
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/mcms"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/aptos/config"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/aptos/operation"
	seq "github.com/smartcontractkit/chainlink/deployment/ccip/changeset/aptos/sequence"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/aptos/utils"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview"
)

/*
	Aptos uses a three-step ownership transfer:
	1. Initiate ownership transfer to a new address
	2. Accept ownership transfer from the address that's pending from the previous step
	3. Execute the (accepted) ownership transfer from the current owner of the token.
	   Required in order to transfer the object itself, which requires a &signer of the current object owner.
	More details in: https://github.com/smartcontractkit/chainlink-aptos/blob/fa2e60d951574f20497d65b05688d89db6a755cd/contracts/managed_token/sources/ownable.move
*/

// Transfer Ownership

var _ cldf.ChangeSetV2[config.TransferTokenOwnershipInput] = TransferTokenOwnership{}

type TransferTokenOwnership struct{}

func (t TransferTokenOwnership) VerifyPreconditions(env cldf.Environment, cfg config.TransferTokenOwnershipInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	for i, transfer := range cfg.Transfers {
		if (transfer.TokenCodeObjectAddress == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("token object address of transfer %d is empty", i))
		}
		if (transfer.To == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("to address of transfer %d is empty", i))
		}
		switch transfer.TokenType {
		case shared.AptosManagedTokenType, shared.AptosRegulatedTokenType:
		default:
			errs = append(errs, fmt.Errorf("token type %v of transfer %d is unsupported", transfer.TokenType.String(), i))
		}
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (t TransferTokenOwnership) Apply(env cldf.Environment, cfg config.TransferTokenOwnershipInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	deps := operation.AptosDeps{
		AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
		CCIPOnChainState: state,
	}
	input := seq.TransferTokenOwnershipsSeqInput{
		Transfers: make([]seq.TokenTransferInput, 0, len(cfg.Transfers)),
	}
	for _, transfer := range cfg.Transfers {
		input.Transfers = append(input.Transfers, seq.TokenTransferInput{
			TokenCodeObjAddress: transfer.TokenCodeObjectAddress,
			To:                  transfer.To,
			TokenType:           transfer.TokenType,
		})
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.TransferTokenOwnershipsSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute TransferTokenOwnershipsSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		[]mcmstypes.BatchOperation{report.Output},
		"Transfers ownership of one or multiple token instances to new addresses",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	return cldf.ChangesetOutput{
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}

// Accept Ownership

var _ cldf.ChangeSetV2[config.AcceptTokenOwnershipInput] = AcceptTokenOwnership{}

type AcceptTokenOwnership struct{}

func (t AcceptTokenOwnership) VerifyPreconditions(env cldf.Environment, cfg config.AcceptTokenOwnershipInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	for i, accept := range cfg.Accepts {
		if (accept.TokenCodeObjectAddress == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("to address of transfer %d is empty", i))
		}
		switch accept.TokenType {
		case shared.AptosManagedTokenType, shared.AptosRegulatedTokenType:
		default:
			errs = append(errs, fmt.Errorf("token type %v of transfer %d is unsupported", accept.TokenType.String(), i))
		}
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (t AcceptTokenOwnership) Apply(env cldf.Environment, cfg config.AcceptTokenOwnershipInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	deps := operation.AptosDeps{
		AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
		CCIPOnChainState: state,
	}
	input := seq.AcceptTokenOwnershipsSeqInput{
		Accepts: make([]seq.TokenAcceptInput, 0, len(cfg.Accepts)),
	}
	for _, accept := range cfg.Accepts {
		input.Accepts = append(input.Accepts, seq.TokenAcceptInput{
			TokenCodeObjAddress: accept.TokenCodeObjectAddress,
			TokenType:           accept.TokenType,
		})
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.AcceptTokenOwnershipsSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute AcceptTokenOwnershipsSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		[]mcmstypes.BatchOperation{report.Output},
		"Accepts ownership of one or multiple token instances",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	return cldf.ChangesetOutput{
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}

// Execute Ownership Transfer

var _ cldf.ChangeSetV2[config.ExecuteTokenOwnershipTransferInput] = ExecuteOwnershipTransfer{}

type ExecuteOwnershipTransfer struct{}

func (t ExecuteOwnershipTransfer) VerifyPreconditions(env cldf.Environment, cfg config.ExecuteTokenOwnershipTransferInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	for i, transfer := range cfg.Transfers {
		if (transfer.TokenCodeObjectAddress == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("token object address of transfer %d is empty", i))
		}
		if (transfer.To == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("to address of transfer %d is empty", i))
		}
		switch transfer.TokenType {
		case shared.AptosManagedTokenType, shared.AptosRegulatedTokenType:
		default:
			errs = append(errs, fmt.Errorf("token type %v of transfer %d is unsupported", transfer.TokenType.String(), i))
		}
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (t ExecuteOwnershipTransfer) Apply(env cldf.Environment, cfg config.ExecuteTokenOwnershipTransferInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	deps := operation.AptosDeps{
		AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
		CCIPOnChainState: state,
	}
	input := seq.ExecuteTokenOwnershipTransfersSeqInput{
		Transfers: make([]seq.TokenTransferInput, 0, len(cfg.Transfers)),
	}
	for _, transfer := range cfg.Transfers {
		input.Transfers = append(input.Transfers, seq.TokenTransferInput{
			TokenCodeObjAddress: transfer.TokenCodeObjectAddress,
			To:                  transfer.To,
			TokenType:           transfer.TokenType,
		})
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.ExecuteTokenOwnershipTransfersSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute ExecuteTokenOwnershipTransfersSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		[]mcmstypes.BatchOperation{report.Output},
		"Executes the pending ownership transfer of one or multiple token instances",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	return cldf.ChangesetOutput{
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}

// Regulated Token - transfer admin

var _ cldf.ChangeSetV2[config.TransferTokenAdminInput] = TransferTokenAdmin{}

type TransferTokenAdmin struct{}

func (t TransferTokenAdmin) VerifyPreconditions(env cldf.Environment, cfg config.TransferTokenAdminInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	for i, transfer := range cfg.Transfers {
		if (transfer.TokenCodeObjectAddress == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("token object address of transfer %d is empty", i))
		}
		if (transfer.To == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("to address of transfer %d is empty", i))
		}
		switch transfer.TokenType {
		case shared.AptosRegulatedTokenType:
		default:
			errs = append(errs, fmt.Errorf("token type %v of transfer %d is unsupported", transfer.TokenType.String(), i))
		}
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (t TransferTokenAdmin) Apply(env cldf.Environment, cfg config.TransferTokenAdminInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	deps := operation.AptosDeps{
		AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
		CCIPOnChainState: state,
	}
	input := seq.TransferTokenAdminsSeqInput{
		Transfers: make([]seq.TokenTransferInput, 0, len(cfg.Transfers)),
	}
	for _, transfer := range cfg.Transfers {
		input.Transfers = append(input.Transfers, seq.TokenTransferInput{
			TokenCodeObjAddress: transfer.TokenCodeObjectAddress,
			To:                  transfer.To,
			TokenType:           transfer.TokenType,
		})
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.TransferTokenAdminsSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute TransferTokenOwnershipsSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		[]mcmstypes.BatchOperation{report.Output},
		"Transfers the admin role of one or multiple regulated token instances to new addresses",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	return cldf.ChangesetOutput{
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}

// Regulated Token - accept admin

var _ cldf.ChangeSetV2[config.AcceptTokenAdminInput] = AcceptTokenAdmin{}

type AcceptTokenAdmin struct{}

func (t AcceptTokenAdmin) VerifyPreconditions(env cldf.Environment, cfg config.AcceptTokenAdminInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	for i, accept := range cfg.Accepts {
		if (accept.TokenCodeObjectAddress == aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("to address of transfer %d is empty", i))
		}
		switch accept.TokenType {
		case shared.AptosRegulatedTokenType:
		default:
			errs = append(errs, fmt.Errorf("token type %v of transfer %d is unsupported", accept.TokenType.String(), i))
		}
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (t AcceptTokenAdmin) Apply(env cldf.Environment, cfg config.AcceptTokenAdminInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	deps := operation.AptosDeps{
		AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
		CCIPOnChainState: state,
	}
	input := seq.AcceptTokenAdminsSeqInput{
		Accepts: make([]seq.TokenAcceptInput, 0, len(cfg.Accepts)),
	}
	for _, accept := range cfg.Accepts {
		input.Accepts = append(input.Accepts, seq.TokenAcceptInput{
			TokenCodeObjAddress: accept.TokenCodeObjectAddress,
			TokenType:           accept.TokenType,
		})
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.AcceptTokenAdminsSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute AcceptTokenOwnershipsSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		[]mcmstypes.BatchOperation{report.Output},
		"Accepts the admin role of one or multiple regulated token instances",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	return cldf.ChangesetOutput{
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}
