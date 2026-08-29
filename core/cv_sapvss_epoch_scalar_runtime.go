package core

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// cvEpochRuntimeScalar holds one process's public context and local keys.
type cvEpochRuntimeScalar struct {
	params        cvScalarParams
	context       *cvLeafContextScalar
	receivers     *cvReceiverKeyMaterialScalar
	validators    *cvValidatorKeyMaterialScalar
	apdbSigner    *tblsThresholdSigner
	controlSigner *tblsThresholdSigner
	coinSigner    *tblsThresholdSigner
	authenticator *cvNetworkAuthenticatorScalar
}

func cvPublicReceiverMaterialScalar(material *cvReceiverKeyMaterialScalar) *cvReceiverKeyMaterialScalar {
	if material == nil {
		return nil
	}
	copy := *material
	copy.receiverOrder = append([]int(nil), material.receiverOrder...)
	copy.receiverIndex = make(map[int]int, len(material.receiverIndex))
	for id, index := range material.receiverIndex {
		copy.receiverIndex[id] = index
	}
	copy.encryptionPublicKeys = append([]bls12381.G1Affine(nil), material.encryptionPublicKeys...)
	copy.identityPublicKeys = make([]ed25519.PublicKey, len(material.identityPublicKeys))
	for i := range material.identityPublicKeys {
		copy.identityPublicKeys[i] = append(ed25519.PublicKey(nil), material.identityPublicKeys[i]...)
	}
	copy.localEncryptionSecrets = make(map[int]fr.Element)
	copy.localIdentitySecrets = make(map[int]ed25519.PrivateKey)
	copy.registryDigest = append([]byte(nil), material.registryDigest...)
	return &copy
}

func cvPublicValidatorMaterialScalar(material *cvValidatorKeyMaterialScalar) *cvValidatorKeyMaterialScalar {
	if material == nil {
		return nil
	}
	copy := *material
	copy.memberOrder = append([]int(nil), material.memberOrder...)
	copy.memberIndex = make(map[int]int, len(material.memberIndex))
	for id, index := range material.memberIndex {
		copy.memberIndex[id] = index
	}
	copy.publicKeys = append([]bls12381.G2Affine(nil), material.publicKeys...)
	copy.localSecrets = make(map[int]fr.Element)
	copy.registryHash = append([]byte(nil), material.registryHash...)
	return &copy
}

// GenerateCVScalarKeyMaterial creates public registries and owner-local keys.
func GenerateCVScalarKeyMaterial(publicDir, secretDir string, cfg Config) (retErr error) {
	c := NormalizeConfig(cfg)
	params, err := cvValidateScalarStartup(c)
	if err != nil {
		return fmt.Errorf("validate CV V2 key generation config: %w", err)
	}
	targets := []string{
		filepath.Join(publicDir, cvReceiverRegistryScalarFilename),
		filepath.Join(publicDir, cvValidatorRegistryScalarFilename),
		filepath.Join(publicDir, cvOldCommitteeKeyBundleScalarFilename),
	}
	for _, receiver := range c.NewCommittee {
		targets = append(targets, cvReceiverScalarEncryptionSecretPath(secretDir, receiver), cvReceiverScalarIdentitySecretPath(secretDir, receiver))
	}
	for _, member := range c.OldCommittee {
		targets = append(targets, cvValidatorScalarSecretPath(secretDir, member))
		for _, role := range []string{cvScalarRoleAPDB, cvScalarRoleControl, cvScalarRoleCoin} {
			targets = append(targets, cvScalarThresholdSecretPath(secretDir, role, member))
		}
	}
	for _, target := range targets {
		if _, err := os.Lstat(target); err == nil {
			return fmt.Errorf("CV V2 key file already exists: %s", target)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	defer func() {
		if retErr != nil {
			for _, target := range targets {
				_ = os.Remove(target)
			}
		}
	}()
	if err := cvGenerateReceiverRegistryScalar(publicDir, secretDir, c.SID, uint64(c.Epoch), c.NewCommittee); err != nil {
		return fmt.Errorf("generate CV V2 receiver registry: %w", err)
	}
	if err := cvGenerateValidatorRegistryScalar(publicDir, secretDir, c.SID, uint64(c.Epoch), c.OldCommittee); err != nil {
		return fmt.Errorf("generate CV V2 validator registry: %w", err)
	}
	if err := cvGenerateOldCommitteeKeyBundleScalar(publicDir, secretDir, c.SID, uint64(c.Epoch), c.OldCommittee, params); err != nil {
		return fmt.Errorf("generate CV V2 old-committee bundle: %w", err)
	}
	return nil
}

func cvLoadEpochRuntimeScalar(cfg Config) (*cvEpochRuntimeScalar, error) {
	c := NormalizeConfig(cfg)
	params, err := cvValidateScalarStartup(c)
	if err != nil {
		return nil, fmt.Errorf("validate CV V2 runtime config: %w", err)
	}
	localOld := sortedUnique(c.LocalNodeIDs)
	localReceivers := sortedUnique(c.CVLocalReceiverIDs)
	if len(localOld) != 1 || len(localReceivers) != 1 {
		return nil, fmt.Errorf("CV V2 runtime requires exactly one local old member and one local receiver")
	}
	receivers, err := cvLoadReceiverRegistryScalar(
		c.CVPublicKeyDir, c.CVLocalSecretDir, c.SID, uint64(c.Epoch), c.NewCommittee, localReceivers,
	)
	if err != nil {
		return nil, fmt.Errorf("load CV V2 receiver material: %w", err)
	}
	validators, err := cvLoadValidatorRegistryScalar(
		c.CVPublicKeyDir, c.CVLocalSecretDir, c.SID, uint64(c.Epoch), c.OldCommittee, localOld,
	)
	if err != nil {
		return nil, fmt.Errorf("load CV V2 validator material: %w", err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleScalar(
		c.CVPublicKeyDir, c.CVLocalSecretDir, c.SID, uint64(c.Epoch), c.OldCommittee, localOld, params,
	)
	if err != nil {
		return nil, fmt.Errorf("load CV V2 threshold material: %w", err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.apdb)
	if err != nil {
		return nil, err
	}
	controlSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.control)
	if err != nil {
		return nil, err
	}
	coinSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.coin)
	if err != nil {
		return nil, err
	}
	authenticator, err := newCVNetworkAuthenticatorScalar(validators, receivers)
	if err != nil {
		return nil, err
	}
	context := &cvLeafContextScalar{
		SID: c.SID, Epoch: uint64(c.Epoch),
		OldRoster: append([]int(nil), c.OldCommittee...), NewRoster: append([]int(nil), c.NewCommittee...),
		ReceiverRegistryDigest: append([]byte(nil), receivers.registryDigest...),
		SharingDegree:          params.newShareDegree,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	if _, err := cvLeafContextScalarCanonicalBytes(context); err != nil {
		return nil, fmt.Errorf("build CV V2 leaf context: %w", err)
	}
	return &cvEpochRuntimeScalar{
		params: params, context: context, receivers: receivers, validators: validators,
		apdbSigner: apdbSigner, controlSigner: controlSigner, coinSigner: coinSigner,
		authenticator: authenticator,
	}, nil
}
