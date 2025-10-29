package changeset_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	ocr3_capability "github.com/smartcontractkit/chainlink-evm/gethwrappers/keystone/generated/ocr3_capability_1_0_0"

	"github.com/smartcontractkit/chainlink/deployment/cre/ocr3/v2/changeset"
	"github.com/smartcontractkit/chainlink/deployment/cre/test"
)

func TestDeployOCR3(t *testing.T) {
	env := test.SetupEnvV2(t, false)

	// Apply the changeset to deploy the V2 capabilities registry
	t.Log("Starting changeset application...")
	changesetOutput, err := changeset.DeployOCR3{}.Apply(*env.Env, changeset.DeployOCR3Input{
		ChainSelector: env.RegistrySelector,
		Qualifier:     "test-ocr3",
	})
	t.Logf("Changeset result: err=%v, output=%v", err, changesetOutput)

	if err != nil {
		t.Fatalf("changeset apply failed: %v", err)
	}
	require.NotNil(t, changesetOutput, "changeset output should not be nil")
	t.Logf("Changeset applied successfully")

	// Verify the datastore contains the deployed contract
	require.NotNil(t, changesetOutput.DataStore, "datastore should not be nil")
	addresses, err := changesetOutput.DataStore.Addresses().Fetch()
	require.NoError(t, err, "should fetch addresses without error")
	t.Logf("Found %d addresses", len(addresses))
	require.Len(t, addresses, 1, "expected exactly one deployed contract")

	// Verify the address is for the correct chain
	deployedAddress := addresses[0]
	require.Equal(t, env.RegistrySelector, deployedAddress.ChainSelector, "deployed contract should be on the correct chain")
	require.NotEmpty(t, deployedAddress.Address, "deployed contract address should not be empty")

	// Verify the contract type is correct
	require.Equal(t, datastore.ContractType("OCR3Capability"), deployedAddress.Type, "contract type should be OCR3Capability")
	require.NotNil(t, deployedAddress.Version, "contract version should be set")

	// Verify reports are generated
	require.NotNil(t, changesetOutput.Reports, "reports should be present")
	require.Len(t, changesetOutput.Reports, 1, "should have exactly one operation report")

	// Further verify the deployed contract by connecting to it
	ocr3Contract, err := ocr3_capability.NewOCR3Capability(common.HexToAddress(deployedAddress.Address), env.Env.BlockChains.EVMChains()[env.RegistrySelector].Client)
	require.NoError(t, err, "failed to create OCR3 contract instance")
	require.NotNil(t, ocr3Contract, "OCR3 contract instance should not be nil")
}
