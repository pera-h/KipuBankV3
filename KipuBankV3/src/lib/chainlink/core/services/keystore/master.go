package keystore

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"sync"

	"github.com/pkg/errors"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/chaintype"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/aptoskey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/cosmoskey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/csakey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/dkgrecipientkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/ethkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/ocr2key"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/ocrkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/p2pkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/solkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/starkkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/suikey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/tonkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/tronkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/vrfkey"
	"github.com/smartcontractkit/chainlink/v2/core/services/keystore/keys/workflowkey"
	"github.com/smartcontractkit/chainlink/v2/core/utils"
)

var (
	ErrLocked      = errors.New("Keystore is locked")
	ErrKeyNotFound = errors.New("Key not found")
	ErrKeyExists   = errors.New("Key already exists")
)

// DefaultEVMChainIDFunc is a func for getting a default evm chain ID -
// necessary because it is lazily evaluated
type DefaultEVMChainIDFunc func() (defaultEVMChainID *big.Int, err error)

type Master interface {
	CSA() CSA
	Eth() Eth
	OCR() OCR
	OCR2() OCR2
	P2P() P2P
	Solana() Solana
	Cosmos() Cosmos
	StarkNet() StarkNet
	Aptos() Aptos
	Tron() Tron
	TON() TON
	Sui() Sui
	VRF() VRF
	Workflow() Workflow
	DKGRecipient() DKGRecipient
	Unlock(ctx context.Context, password string) error
	IsEmpty(ctx context.Context) (bool, error)
}
type master struct {
	*keyManager
	cosmos       *cosmos
	csa          *csa
	eth          *eth
	ocr          *ocr
	ocr2         ocr2
	p2p          *p2p
	solana       *solana
	starknet     *starknet
	sui          *sui
	aptos        *aptos
	tron         *tron
	ton          *ton
	vrf          *vrf
	workflow     *workflow
	dkgRecipient *dkgRecipient
}

type Logf func(string, ...any)

func New(ds sqlutil.DataSource, scryptParams utils.ScryptParams, announce Logf) Master {
	return newMaster(ds, scryptParams, announce)
}

func newMaster(ds sqlutil.DataSource, scryptParams utils.ScryptParams, announce Logf) *master {
	orm := NewORM(ds)
	km := &keyManager{
		orm:          orm,
		keystateORM:  orm,
		scryptParams: scryptParams,
		lock:         &sync.RWMutex{},
		announce:     announcer(announce),
	}

	return &master{
		keyManager:   km,
		cosmos:       newCosmosKeyStore(km),
		csa:          newCSAKeyStore(km),
		eth:          newEthKeyStore(km, orm, orm.ds),
		ocr:          newOCRKeyStore(km),
		ocr2:         newOCR2KeyStore(km),
		p2p:          newP2PKeyStore(km),
		solana:       newSolanaKeyStore(km),
		starknet:     newStarkNetKeyStore(km),
		sui:          newSuiKeyStore(km),
		aptos:        newAptosKeyStore(km),
		tron:         newTronKeyStore(km),
		ton:          newTONKeyStore(km),
		vrf:          newVRFKeyStore(km),
		workflow:     newWorkflowKeyStore(km),
		dkgRecipient: newDKGRecipientKeyStore(km),
	}
}

func (ks master) CSA() CSA {
	return ks.csa
}

func (ks *master) Eth() Eth {
	return ks.eth
}

func (ks *master) OCR() OCR {
	return ks.ocr
}

func (ks *master) OCR2() OCR2 {
	return ks.ocr2
}

func (ks *master) P2P() P2P {
	return ks.p2p
}

func (ks *master) Solana() Solana {
	return ks.solana
}

func (ks *master) Cosmos() Cosmos {
	return ks.cosmos
}

func (ks *master) StarkNet() StarkNet {
	return ks.starknet
}

func (ks *master) Aptos() Aptos {
	return ks.aptos
}

func (ks *master) Tron() Tron {
	return ks.tron
}

func (ks *master) TON() TON {
	return ks.ton
}

func (ks *master) Sui() Sui {
	return ks.sui
}

func (ks *master) VRF() VRF {
	return ks.vrf
}

func (ks *master) Workflow() Workflow {
	return ks.workflow
}

func (ks *master) DKGRecipient() DKGRecipient {
	return ks.dkgRecipient
}

type ORM interface {
	isEmpty(context.Context) (bool, error)
	saveEncryptedKeyRing(context.Context, *encryptedKeyRing, ...func(sqlutil.DataSource) error) error
	getEncryptedKeyRing(context.Context) (encryptedKeyRing, error)
}

type keystateORM interface {
	loadKeyStates(context.Context) (*keyStates, error)
}

type keyManager struct {
	orm          ORM
	keystateORM  keystateORM
	scryptParams utils.ScryptParams
	keyRing      *keyRing
	keyStates    *keyStates
	lock         *sync.RWMutex
	password     string
	announce     func(Key)
}

func (km *keyManager) IsEmpty(ctx context.Context) (bool, error) {
	return km.orm.isEmpty(ctx)
}

func (km *keyManager) Unlock(ctx context.Context, password string) error {
	km.lock.Lock()
	defer km.lock.Unlock()
	// DEV: allow Unlock() to be idempotent - this is especially useful in tests,
	if km.password != "" {
		if password != km.password {
			return errors.New("attempting to unlock keystore again with a different password")
		}
		return nil
	}
	ekr, err := km.orm.getEncryptedKeyRing(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to get encrypted key ring")
	}
	kr, err := ekr.Decrypt(password)
	if err != nil {
		return errors.Wrap(err, "unable to decrypt encrypted key ring")
	}
	km.keyRing = kr

	ks, err := km.keystateORM.loadKeyStates(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to load key states")
	}
	km.keyStates = ks

	km.password = password
	return nil
}

// caller must hold lock!
func (km *keyManager) save(ctx context.Context, callbacks ...func(sqlutil.DataSource) error) error {
	ekb, err := km.keyRing.Encrypt(km.password, km.scryptParams)
	if err != nil {
		return errors.Wrap(err, "unable to encrypt keyRing")
	}
	return km.orm.saveEncryptedKeyRing(ctx, &ekb, callbacks...)
}

// caller must hold lock!
func (km *keyManager) safeAddKey(ctx context.Context, unknownKey Key, callbacks ...func(sqlutil.DataSource) error) error {
	fieldName, err := GetFieldNameForKey(unknownKey)
	if err != nil {
		return err
	}
	// add key to keyring
	id := reflect.ValueOf(unknownKey.ID())
	key := reflect.ValueOf(unknownKey)
	keyRing := reflect.Indirect(reflect.ValueOf(km.keyRing))
	keyMap := keyRing.FieldByName(fieldName)
	keyMap.SetMapIndex(id, key)
	// save keyring to DB
	err = km.save(ctx, callbacks...)
	// if save fails, remove key from keyring
	if err != nil {
		keyMap.SetMapIndex(id, reflect.Value{})
		return err
	}
	return nil
}

// caller must hold lock!
func (km *keyManager) safeRemoveKey(ctx context.Context, unknownKey Key, callbacks ...func(sqlutil.DataSource) error) (err error) {
	fieldName, err := GetFieldNameForKey(unknownKey)
	if err != nil {
		return err
	}
	id := reflect.ValueOf(unknownKey.ID())
	key := reflect.ValueOf(unknownKey)
	keyRing := reflect.Indirect(reflect.ValueOf(km.keyRing))
	keyMap := keyRing.FieldByName(fieldName)
	keyMap.SetMapIndex(id, reflect.Value{})
	// save keyring to DB
	err = km.save(ctx, callbacks...)
	// if save fails, add key back to keyRing
	if err != nil {
		keyMap.SetMapIndex(id, key)
		return err
	}
	return nil
}

// caller must hold lock!
func (km *keyManager) isLocked() bool {
	return len(km.password) == 0
}

func GetFieldNameForKey(unknownKey Key) (string, error) {
	switch unknownKey.(type) {
	case cosmoskey.Key:
		return "Cosmos", nil
	case csakey.KeyV2:
		return "CSA", nil
	case ethkey.KeyV2:
		return "Eth", nil
	case ocrkey.KeyV2:
		return "OCR", nil
	case ocr2key.KeyBundle:
		return "OCR2", nil
	case p2pkey.KeyV2:
		return "P2P", nil
	case solkey.Key:
		return "Solana", nil
	case starkkey.Key:
		return "StarkNet", nil
	case aptoskey.Key:
		return "Aptos", nil
	case tronkey.Key:
		return "Tron", nil
	case tonkey.Key:
		return "TON", nil
	case suikey.Key:
		return "Sui", nil
	case vrfkey.KeyV2:
		return "VRF", nil
	case workflowkey.Key:
		return "Workflow", nil
	case dkgrecipientkey.Key:
		return "DKGRecipient", nil
	}
	return "", fmt.Errorf("unknown key type: %T", unknownKey)
}

type Key interface {
	ID() string
}

// announcer creates a new key announcer which controls logging to prevent leaking keys.
func announcer(logf Logf) func(key Key) {
	return func(key Key) {
		kind, err := GetFieldNameForKey(key)
		if err != nil {
			kind = "[" + err.Error() + "]"
		}
		if ct, ok := key.(interface{ ChainType() chaintype.ChainType }); ok {
			logf("Created %s key with ID %s for chain %s", kind, key.ID(), ct.ChainType())
		} else {
			logf("Created %s key with ID %s", kind, key.ID())
		}
	}
}
