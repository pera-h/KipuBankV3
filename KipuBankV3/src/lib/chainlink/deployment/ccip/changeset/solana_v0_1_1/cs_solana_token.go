package solana

import (
	"context"
	"errors"
	"fmt"

	tokenMetadata "github.com/gagliardetto/metaplex-go/clients/token-metadata"
	"github.com/gagliardetto/solana-go"
	solToken "github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/smartcontractkit/mcms"
	mcmsTypes "github.com/smartcontractkit/mcms/types"

	cldf_solana "github.com/smartcontractkit/chainlink-deployments-framework/chain/solana"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink/deployment/ccip/shared/stateview"
	"github.com/smartcontractkit/chainlink/deployment/common/proposalutils"

	solCommonUtil "github.com/smartcontractkit/chainlink-ccip/chains/solana/utils/common"
	solTokenUtil "github.com/smartcontractkit/chainlink-ccip/chains/solana/utils/tokens"
)

// use this changest to deploy a token, create ATAs and mint the token to those ATAs
var _ cldf.ChangeSet[DeploySolanaTokenConfig] = DeploySolanaToken

// use this changeset to mint the token to an address
var _ cldf.ChangeSet[MintSolanaTokenConfig] = MintSolanaToken

// use this changeset to create ATAs for a token
var _ cldf.ChangeSet[CreateSolanaTokenATAConfig] = CreateSolanaTokenATA

// use this changeset to set the authority of a token
var _ cldf.ChangeSet[SetTokenAuthorityConfig] = SetTokenAuthority

// use this changeset to upload or update token metadata
var _ cldf.ChangeSet[UploadTokenMetadataConfig] = UploadTokenMetadata

const MplTokenMetadataProgramName = "MplTokenMetadataProgramName"

// discriminator for update_metadata_account_v2 ix
const UpdateMetadataAccountV2Ix = 15

// discriminator for create_metadata_account
const CreateMetadataAccountV2Ix = 16

func getMintIxs(e cldf.Environment, chain cldf_solana.Chain, tokenprogramID, mint solana.PublicKey, amountToAddress map[string]uint64) error {
	for toAddress, amount := range amountToAddress {
		e.Logger.Infof("Minting %d to %s", amount, toAddress)
		toAddressBase58 := solana.MustPublicKeyFromBase58(toAddress)
		// get associated token account for toAddress
		ata, _, _ := solTokenUtil.FindAssociatedTokenAddress(tokenprogramID, mint, toAddressBase58)
		mintToI, err := solTokenUtil.MintTo(amount, tokenprogramID, mint, ata, chain.DeployerKey.PublicKey())
		if err != nil {
			return err
		}
		if err := chain.Confirm([]solana.Instruction{mintToI}); err != nil {
			e.Logger.Errorw("Failed to confirm instructions for minting", "chain", chain.String(), "err", err)
			return err
		}
	}
	return nil
}

func createATAIx(e cldf.Environment, chain cldf_solana.Chain, tokenprogramID, mint solana.PublicKey, ataList []string) error {
	for _, ata := range ataList {
		e.Logger.Infof("Creating ATA for account %s for token %s", ata, mint.String())
		createATAIx, _, err := solTokenUtil.CreateAssociatedTokenAccount(
			tokenprogramID,
			mint,
			solana.MustPublicKeyFromBase58(ata),
			chain.DeployerKey.PublicKey(),
		)
		if err != nil {
			return err
		}
		if err := chain.Confirm([]solana.Instruction{createATAIx}); err != nil {
			e.Logger.Errorw("Failed to confirm instructions for ATA creation", "chain", chain.String(), "err", err)
			return err
		}
	}
	return nil
}

// TODO: add option to set token mint authority by taking in its public key
// might need to take authority private key if it needs to sign that
type DeploySolanaTokenConfig struct {
	ChainSelector       uint64
	TokenProgramName    cldf.ContractType
	TokenDecimals       uint8
	TokenSymbol         string
	MintPrivateKey      solana.PrivateKey // optional, if not provided, a new key will be generated
	ATAList             []string          // addresses to create ATAs for
	MintAmountToAddress map[string]uint64 // address -> amount
	// if true, sets token freeze authority to nil otherwise sets to timelock
	// WARNING: IF WE DISABLE THE FREEZE AUTHORITY IT IS IRREVERSIBLE
	DisableFreezeAuthority bool
}

func NewTokenInstruction(e *cldf.Environment, chain cldf_solana.Chain, cfg DeploySolanaTokenConfig) ([]solana.Instruction, solana.PrivateKey, error) {
	tokenprogramID, err := GetTokenProgramID(cfg.TokenProgramName)
	if err != nil {
		return nil, nil, err
	}

	// token mint authority
	// can accept a private key in config and pass in pub key here and private key as signer
	timelockSignerPDA, err := FetchTimelockSigner(*e, cfg.ChainSelector)
	if err != nil {
		return nil, nil, err
	}
	freezeAuthority := timelockSignerPDA
	tokenAdminPubKey := chain.DeployerKey.PublicKey()
	// if we're disabling the freeze authority, we first set it to the deployer key so it can
	// immediately revoke it
	if cfg.DisableFreezeAuthority {
		freezeAuthority = chain.DeployerKey.PublicKey()
	}
	var mint solana.PublicKey
	var mintPrivKey solana.PrivateKey
	privKey := cfg.MintPrivateKey
	if privKey.IsValid() {
		mint = privKey.PublicKey()
		mintPrivKey = privKey
	} else {
		mintPrivKey, err = solana.NewRandomPrivateKey()
		if err != nil {
			return nil, nil, err
		}
		mint = mintPrivKey.PublicKey()
	}
	instructions, err := solTokenUtil.CreateTokenWith(
		context.Background(),
		tokenprogramID,
		mint,
		tokenAdminPubKey,
		freezeAuthority,
		cfg.TokenDecimals,
		chain.Client,
		cldf_solana.SolDefaultCommitment,
		false,
	)
	if err != nil {
		return nil, nil, err
	}
	return instructions, mintPrivKey, nil
}

func DeploySolanaToken(e cldf.Environment, cfg DeploySolanaTokenConfig) (cldf.ChangesetOutput, error) {
	chain, ok := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	if !ok {
		return cldf.ChangesetOutput{}, fmt.Errorf("chain %d not found in environment", cfg.ChainSelector)
	}
	tokenprogramID, err := GetTokenProgramID(cfg.TokenProgramName)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	// create token ix
	instructions, mintPrivKey, err := NewTokenInstruction(&e, chain, cfg)
	mint := mintPrivKey.PublicKey()
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	err = chain.Confirm(instructions, solCommonUtil.AddSigners(mintPrivKey))
	if err != nil {
		e.Logger.Errorw("Failed to confirm instructions for token deployment", "chain", chain.String(), "err", err)
		return cldf.ChangesetOutput{}, err
	}

	// ata ix
	err = createATAIx(e, chain, tokenprogramID, mint, cfg.ATAList)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	// mint ix
	err = getMintIxs(e, chain, tokenprogramID, mint, cfg.MintAmountToAddress)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	newAddresses := cldf.NewMemoryAddressBook()
	tv := cldf.NewTypeAndVersion(cfg.TokenProgramName, deployment.Version1_0_0)
	tv.AddLabel(cfg.TokenSymbol)
	err = newAddresses.Save(cfg.ChainSelector, mint.String(), tv)
	if err != nil {
		e.Logger.Errorw("Failed to save token", "chain", chain.String(), "err", err)
		return cldf.ChangesetOutput{}, err
	}

	e.Logger.Infow("Deployed contract", "Contract", tv.String(), "addr", mint.String(), "chain", chain.String())
	if cfg.DisableFreezeAuthority {
		_, err := DisableFreezeAuthority(e, DisableFreezeAuthorityConfig{
			ChainSelector: cfg.ChainSelector,
			TokenPubkeys:  []solana.PublicKey{mint},
		})
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
	}

	return cldf.ChangesetOutput{
		AddressBook: newAddresses,
	}, nil
}

type MintSolanaTokenConfig struct {
	ChainSelector   uint64
	TokenPubkey     string
	AmountToAddress map[string]uint64 // address -> amount
}

func (cfg MintSolanaTokenConfig) Validate(e cldf.Environment) error {
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	tokenAddress := solana.MustPublicKeyFromBase58(cfg.TokenPubkey)
	state, err := stateview.LoadOnchainState(e)
	if err != nil {
		return err
	}
	chainState := state.SolChains[cfg.ChainSelector]
	tokenprogramID, err := chainState.TokenToTokenProgram(tokenAddress)
	if err != nil {
		return err
	}

	accountInfo, err := chain.Client.GetAccountInfoWithOpts(e.GetContext(), tokenAddress, &rpc.GetAccountInfoOpts{
		Commitment: cldf_solana.SolDefaultCommitment,
	})
	if err != nil {
		fmt.Println("error getting account info", err)
		return err
	}
	if accountInfo == nil || accountInfo.Value == nil {
		return fmt.Errorf("token address %s not found", tokenAddress.String())
	}
	if accountInfo.Value.Owner != tokenprogramID {
		return fmt.Errorf("token address %s is not owned by the SPL token program", tokenAddress.String())
	}
	return nil
}

func MintSolanaToken(e cldf.Environment, cfg MintSolanaTokenConfig) (cldf.ChangesetOutput, error) {
	err := cfg.Validate(e)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	// get chain
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	state, _ := stateview.LoadOnchainState(e)
	chainState := state.SolChains[cfg.ChainSelector]
	// get addresses
	tokenAddress := solana.MustPublicKeyFromBase58(cfg.TokenPubkey)
	// get token program id
	tokenprogramID, _ := chainState.TokenToTokenProgram(tokenAddress)

	// get mint instructions
	err = getMintIxs(e, chain, tokenprogramID, tokenAddress, cfg.AmountToAddress)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	e.Logger.Infow("Minted tokens on", "chain", cfg.ChainSelector, "for token", tokenAddress.String())

	return cldf.ChangesetOutput{}, nil
}

type CreateSolanaTokenATAConfig struct {
	ChainSelector uint64
	TokenPubkey   solana.PublicKey
	TokenProgram  cldf.ContractType
	ATAList       []string // addresses to create ATAs for
}

func CreateSolanaTokenATA(e cldf.Environment, cfg CreateSolanaTokenATAConfig) (cldf.ChangesetOutput, error) {
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	state, _ := stateview.LoadOnchainState(e)
	chainState := state.SolChains[cfg.ChainSelector]

	tokenprogramID, err := chainState.TokenToTokenProgram(cfg.TokenPubkey)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	// create instructions for each ATA
	err = createATAIx(e, chain, tokenprogramID, cfg.TokenPubkey, cfg.ATAList)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	e.Logger.Infow("Created ATAs on", "chain", cfg.ChainSelector, "for token", cfg.TokenPubkey.String(), "numATAs", len(cfg.ATAList))

	return cldf.ChangesetOutput{}, nil
}

type TokenAuthorityConfig struct {
	AuthorityType solToken.AuthorityType
	TokenPubkey   solana.PublicKey
	NewAuthority  solana.PublicKey
}

type SetTokenAuthorityConfig struct {
	ChainSelector         uint64
	TokenAuthorityConfigs []TokenAuthorityConfig
	MCMS                  *proposalutils.TimelockConfig
}

func SetTokenAuthority(e cldf.Environment, cfg SetTokenAuthorityConfig) (cldf.ChangesetOutput, error) {
	if cfg.ChainSelector == 0 {
		return cldf.ChangesetOutput{}, errors.New("chain selector is required")
	}
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	state, err := stateview.LoadOnchainStateSolana(e)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	chainState, ok := state.SolChains[cfg.ChainSelector]
	if !ok {
		return cldf.ChangesetOutput{}, fmt.Errorf("chain %d not found in environment", cfg.ChainSelector)
	}

	timelockSignerPDA, err := FetchTimelockSigner(e, cfg.ChainSelector)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("error loading timelockSignerPDA: %w", err)
	}
	e.Logger.Infow("Fetched timelock signer PDA", "timelockSignerPDA", timelockSignerPDA.String())
	mcmsTxs := []mcmsTypes.Transaction{}

	for _, tokenAuthorityConfig := range cfg.TokenAuthorityConfigs {
		tokenprogramID, err := chainState.TokenToTokenProgram(tokenAuthorityConfig.TokenPubkey)
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		var tokenMint solToken.Mint
		if err = chain.GetAccountDataBorshInto(e.GetContext(), tokenAuthorityConfig.TokenPubkey, &tokenMint); err != nil {
			return cldf.ChangesetOutput{}, err
		}
		e.Logger.Infow("Fetched token mint", "MintAuthority", tokenMint.MintAuthority.String(), "tokenMintFreezeAuthority", tokenMint.FreezeAuthority.String())
		authority := chain.DeployerKey.PublicKey()
		switch tokenAuthorityConfig.AuthorityType {
		case solToken.AuthorityMintTokens:
			if tokenMint.MintAuthority != nil {
				authority = *tokenMint.MintAuthority
			}
		case solToken.AuthorityFreezeAccount:
			if tokenMint.FreezeAuthority != nil {
				authority = *tokenMint.FreezeAuthority
			}
		default:
			return cldf.ChangesetOutput{}, fmt.Errorf("unsupported authority type: %d", tokenAuthorityConfig.AuthorityType)
		}
		e.Logger.Infow("Setting token authority", "tokenPubkey", tokenAuthorityConfig.TokenPubkey.String(), "authorityType", tokenAuthorityConfig.AuthorityType, "currentAuthority", authority.String(), "newAuthority", tokenAuthorityConfig.NewAuthority.String())
		isAuthorityTimelockSigner := authority.Equals(timelockSignerPDA)

		ix, err := solToken.NewSetAuthorityInstruction(
			tokenAuthorityConfig.AuthorityType,
			tokenAuthorityConfig.NewAuthority,
			tokenAuthorityConfig.TokenPubkey,
			authority,
			solana.PublicKeySlice{},
		).ValidateAndBuild()
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		tokenIx := &solTokenUtil.TokenInstruction{Instruction: ix, Program: tokenprogramID}

		if isAuthorityTimelockSigner {
			tx, err := BuildMCMSTxn(tokenIx, tokenprogramID.String(), shared.SPLTokens)
			if err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to create transaction: %w", err)
			}
			mcmsTxs = append(mcmsTxs, *tx)
		} else {
			if err = chain.Confirm([]solana.Instruction{tokenIx}); err != nil {
				e.Logger.Errorw("Failed to confirm instructions for SetTokenAuthority", "chain", chain.String(), "err", err)
				return cldf.ChangesetOutput{}, err
			}
		}
		e.Logger.Infow("Set token authority on", "chain", cfg.ChainSelector, "for token", tokenAuthorityConfig.TokenPubkey.String(), "newAuthority", tokenAuthorityConfig.NewAuthority.String(), "authorityType", tokenAuthorityConfig.AuthorityType)
	}

	if len(mcmsTxs) > 0 {
		proposal, err := BuildProposalsForTxns(
			e, cfg.ChainSelector, "proposal to SetTokenAuthority in Solana", cfg.MCMS.MinDelay, mcmsTxs)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to build proposal: %w", err)
		}
		return cldf.ChangesetOutput{
			MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		}, nil
	}

	return cldf.ChangesetOutput{}, nil
}

type TokenMetadata struct {
	TokenPubkey solana.PublicKey
	// https://metaboss.dev/create.html#metadata
	// only to be provided on initial upload, it takes in name, symbol, uri
	// after initial upload, those fields can be updated using the update inputs
	// put the json in ccip/env/input dir in CLD
	MetadataJSONPath string
	UpdateAuthority  solana.PublicKey // used to set update authority of the token metadata PDA after initial upload
	// https://metaboss.dev/update.html#update-name
	UpdateName string // used to update the name of the token metadata PDA after initial upload
	// https://metaboss.dev/update.html#update-symbol
	UpdateSymbol string // used to update the symbol of the token metadata PDA after initial upload
	// https://metaboss.dev/update.html#update-uri
	UpdateURI string // used to update the uri of the token metadata PDA after initial upload
}

type UploadTokenMetadataConfig struct {
	ChainSelector uint64
	TokenMetadata []TokenMetadata
	MCMS          *proposalutils.TimelockConfig // timelock config for mcms
}

func (cfg UploadTokenMetadataConfig) Validate(e cldf.Environment) error {
	for _, metadata := range cfg.TokenMetadata {
		if metadata.TokenPubkey.IsZero() {
			e.Logger.Errorw("Token pubkey is zero", "tokenPubkey", metadata.TokenPubkey.String())
			return errors.New("token pubkey is zero")
		}
		var tokenMetadata tokenMetadata.Metadata
		metadataPDA, err := deployment.FindMplTokenMetadataPDA(metadata.TokenPubkey)
		if err != nil {
			return fmt.Errorf("failed to find metadata PDA: %w", err)
		}
		if err = e.BlockChains.SolanaChains()[cfg.ChainSelector].GetAccountDataBorshInto(context.Background(), metadataPDA, &tokenMetadata); err != nil {
			// PDA does not exist. We need to create it. Validate fields
			if metadata.MetadataJSONPath == "" {
				e.Logger.Infow("Metadata JSON path is empty", "tokenPubkey", metadata.TokenPubkey.String())
				return errors.New("metadata JSON path is empty")
			}
		}
	}
	return nil
}

func UploadTokenMetadata(e cldf.Environment, cfg UploadTokenMetadataConfig) (cldf.ChangesetOutput, error) {
	if err := cfg.Validate(e); err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("error validating upload token metadata config: %w", err)
	}
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	mcmsTxs := make([]mcmsTypes.Transaction, 0)

	out1, err1 := RunCommand("solana", []string{"config", "set", "--url", chain.URL}, chain.ProgramsPath)
	e.Logger.Infow("solana config set url output", "output", out1)
	if err1 != nil {
		e.Logger.Errorw("solana config set url error", "error", err1)
		return cldf.ChangesetOutput{}, fmt.Errorf("error setting solana url: %w", err1)
	}
	out2, err2 := RunCommand("solana", []string{"config", "set", "--keypair", chain.KeypairPath}, chain.ProgramsPath)
	e.Logger.Infow("solana config set keypair output", "output", out2)
	if err2 != nil {
		e.Logger.Errorw("solana config set keypair error", "error", err2)
		return cldf.ChangesetOutput{}, fmt.Errorf("error setting solana keypair: %w", err2)
	}
	timelockSignerPDA, err := FetchTimelockSigner(e, cfg.ChainSelector)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("error fetching timelock signer PDA: %w", err)
	}
	for _, metadata := range cfg.TokenMetadata {
		// initial upload
		if metadata.MetadataJSONPath != "" {
			e.Logger.Infow("Uploading token metadata", "tokenPubkey", metadata.TokenPubkey.String())
			args := []string{"create", "metadata", "--mint", metadata.TokenPubkey.String(), "--metadata", metadata.MetadataJSONPath}
			e.Logger.Info(args)
			output, err := RunCommand("metaboss", args, chain.ProgramsPath)
			e.Logger.Infow("metaboss output", "output", output)
			if err != nil {
				e.Logger.Errorw("metaboss create error", "error", err)
				return cldf.ChangesetOutput{}, fmt.Errorf("error uploading token metadata: %w", err)
			}
			e.Logger.Infow("Token metadata uploaded", "tokenPubkey", metadata.TokenPubkey.String())
			continue
		}

		tokenMint := metadata.TokenPubkey
		var mintMetadata tokenMetadata.Metadata
		metadataPDA, metadataErr := deployment.FindMplTokenMetadataPDA(tokenMint)
		if metadataErr != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("error finding metadata account: %w", metadataErr)
		}
		fmt.Println("Metadata", metadataPDA)
		if err := e.BlockChains.SolanaChains()[cfg.ChainSelector].GetAccountDataBorshInto(context.Background(), metadataPDA, &mintMetadata); err != nil {
			e.Logger.Errorw("Token metadata account does not exist. Cannot update", "tokenPubkey", metadata.TokenPubkey.String())
			continue
		}
		newUpdateAuthority := mintMetadata.UpdateAuthority
		newData := tokenMetadata.DataV2{
			Name:   mintMetadata.Data.Name,
			Symbol: mintMetadata.Data.Symbol,
			Uri:    mintMetadata.Data.Uri,
		}
		if !metadata.UpdateAuthority.IsZero() {
			newUpdateAuthority = metadata.UpdateAuthority
		}
		if metadata.UpdateName != "" {
			newData.Name = metadata.UpdateName
		}
		if metadata.UpdateSymbol != "" {
			newData.Symbol = metadata.UpdateSymbol
		}
		if metadata.UpdateURI != "" {
			newData.Uri = metadata.UpdateURI
		}
		e.Logger.Infow("Updating token metadata authority", "metadataPDA", metadataPDA, "authority", mintMetadata.UpdateAuthority, "data", newData)
		instruction, err := modifyTokenMetadataIx(
			metadataPDA, mintMetadata.UpdateAuthority, &newUpdateAuthority, &newData)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("error generating modify metadata ix: %w", err)
		}
		if mintMetadata.UpdateAuthority.Equals(timelockSignerPDA) {
			upgradeTx, err := BuildMCMSTxn(&instruction, deployment.MplTokenMetadataID.String(), MplTokenMetadataProgramName)
			if err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to create upgrade transaction: %w", err)
			}
			if upgradeTx != nil {
				mcmsTxs = append(mcmsTxs, *upgradeTx)
			}
		} else {
			if err := e.BlockChains.SolanaChains()[cfg.ChainSelector].Confirm([]solana.Instruction{&instruction}); err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to confirm instructions: %w", err)
			}
		}
	}

	return generateProposalIfMCMS(e, cfg.ChainSelector, cfg.MCMS, mcmsTxs)
}

func modifyTokenMetadataIx(
	metadataPDA, authority solana.PublicKey,
	newAuthority *solana.PublicKey,
	newData *tokenMetadata.DataV2,
) (solana.GenericInstruction, error) {
	args := tokenMetadata.UpdateMetadataAccountArgsV2{
		Data:            newData,
		UpdateAuthority: newAuthority,
	}
	ix := tokenMetadata.NewUpdateMetadataAccountV2Instruction(
		args,
		metadataPDA,
		authority).Build()
	data, err := ix.Data()
	if err != nil {
		return solana.GenericInstruction{}, fmt.Errorf("error building update metadata account data: %w", err)
	}

	instruction := solana.NewInstruction(
		deployment.MplTokenMetadataID,
		ix.Accounts(),
		data,
	)
	return *instruction, nil
}

type DisableFreezeAuthorityConfig struct {
	ChainSelector uint64
	TokenPubkeys  []solana.PublicKey
}

func DisableFreezeAuthority(e cldf.Environment, cfg DisableFreezeAuthorityConfig) (cldf.ChangesetOutput, error) {
	if cfg.ChainSelector == 0 {
		return cldf.ChangesetOutput{}, errors.New("chain selector is required")
	}
	chain := e.BlockChains.SolanaChains()[cfg.ChainSelector]
	out1, err1 := RunCommand("solana", []string{"config", "set", "--url", chain.URL}, chain.ProgramsPath)
	e.Logger.Infow("solana config set url output", "output", out1)
	if err1 != nil {
		e.Logger.Errorw("solana config set url error", "error", err1)
		return cldf.ChangesetOutput{}, fmt.Errorf("error setting solana url: %w", err1)
	}
	out2, err2 := RunCommand("solana", []string{"config", "set", "--keypair", chain.KeypairPath}, chain.ProgramsPath)
	e.Logger.Infow("solana config set keypair output", "output", out2)
	if err2 != nil {
		e.Logger.Errorw("solana config set keypair error", "error", err2)
		return cldf.ChangesetOutput{}, fmt.Errorf("error setting solana keypair: %w", err2)
	}

	for _, tokenPubkey := range cfg.TokenPubkeys {
		e.Logger.Infow("Disabling freeze authority", "tokenPubkey", tokenPubkey.String())
		args := []string{"authorize", tokenPubkey.String(), "freeze", "--disable"}
		e.Logger.Info(args)
		output, err := RunCommand("spl-token", args, chain.ProgramsPath)
		e.Logger.Debugw("spl-token output", "output", output)
		if err != nil {
			e.Logger.Debugw("spl-token authorize error", "error", err)
			return cldf.ChangesetOutput{}, fmt.Errorf("error disabling freeze authority: %w", err)
		}
		e.Logger.Infow("Token freeze authority disabled", "tokenPubkey", tokenPubkey.String())
	}
	return cldf.ChangesetOutput{}, nil
}
