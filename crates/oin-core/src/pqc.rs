
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as DsaSerDes, Signer, Verifier};
use fips205::slh_dsa_shake_256s;
use fips205::traits::{SerDes as SlhSerDes, Signer as SlhSigner, Verifier as SlhVerifier};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

use crate::crypto::{self, DataKey, SealedBlock, KEY_LEN};
use crate::error::{OinError, Result};

pub const KEM_ENCAPS_KEY_LEN: usize = 1568;
pub const KEM_DECAPS_KEY_LEN: usize = 3168;
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
pub const KEM_SHARED_SECRET_LEN: usize = 32;

pub const DSA_PUBLIC_KEY_LEN: usize = 2592;
pub const DSA_SECRET_KEY_LEN: usize = 4896;
pub const DSA_SIGNATURE_LEN: usize = 4627;

pub const SLH_PUBLIC_KEY_LEN: usize = 64;
pub const SLH_SECRET_KEY_LEN: usize = 128;
pub const SLH_SIGNATURE_LEN: usize = 29_792;

#[derive(Clone, Serialize, Deserialize)]
pub struct KemEncapsKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct KemDecapsKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct KemCiphertext(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct DsaPublicKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct DsaSecretKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct DsaSignature(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct SlhPublicKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct SlhSecretKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct SlhSignature(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize)]
pub struct KemKeypair {
    pub encaps_key: KemEncapsKey,
    pub decaps_key: KemDecapsKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DsaKeypair {
    pub public_key: DsaPublicKey,
    pub secret_key: DsaSecretKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SlhKeypair {
    pub public_key: SlhPublicKey,
    pub secret_key: SlhSecretKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DualSigningKeys {
    pub dsa: DsaKeypair,
    pub slh: SlhKeypair,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DualVerifyKeys {
    pub dsa_pk: DsaPublicKey,
    pub slh_pk: SlhPublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PqcEnvelope {
    pub version: u8,
    pub kem_ciphertext: KemCiphertext,
    pub sealed: SealedBlock,
    pub signature: Option<DsaSignature>,
    #[serde(default)]
    pub slh_signature: Option<SlhSignature>,
}

pub fn kem_keygen() -> Result<KemKeypair> {
    let (ek, dk) = ml_kem_1024::KG::try_keygen()
        .map_err(|_| OinError::Encryption("ML-KEM-1024 keygen failed".into()))?;

    Ok(KemKeypair {
        encaps_key: KemEncapsKey(ek.into_bytes().to_vec()),
        decaps_key: KemDecapsKey(dk.into_bytes().to_vec()),
    })
}

pub fn kem_encapsulate(encaps_key: &KemEncapsKey) -> Result<(KemCiphertext, [u8; 32])> {
    let ek_bytes: [u8; KEM_ENCAPS_KEY_LEN] = encaps_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Encryption("invalid encaps key length".into()))?;

    let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes)
        .map_err(|_| OinError::Encryption("invalid ML-KEM encaps key".into()))?;

    let (ssk, ct) = ek.try_encaps()
        .map_err(|_| OinError::Encryption("ML-KEM encapsulation failed".into()))?;

    Ok((
        KemCiphertext(ct.into_bytes().to_vec()),
        ssk.into_bytes(),
    ))
}

pub fn kem_decapsulate(decaps_key: &KemDecapsKey, ciphertext: &KemCiphertext) -> Result<[u8; 32]> {
    let dk_bytes: [u8; KEM_DECAPS_KEY_LEN] = decaps_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid decaps key length".into()))?;

    let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes)
        .map_err(|_| OinError::Decryption("invalid ML-KEM decaps key".into()))?;

    let ct_bytes: [u8; KEM_CIPHERTEXT_LEN] = ciphertext.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid ciphertext length".into()))?;

    let ct = ml_kem_1024::CipherText::try_from_bytes(ct_bytes)
        .map_err(|_| OinError::Decryption("invalid ML-KEM ciphertext".into()))?;

    let ssk = dk.try_decaps(&ct)
        .map_err(|_| OinError::Decryption("ML-KEM decapsulation failed".into()))?;

    Ok(ssk.into_bytes())
}

pub fn dsa_keygen() -> Result<DsaKeypair> {
    let (pk, sk) = ml_dsa_87::try_keygen()
        .map_err(|_| OinError::Encryption("ML-DSA-87 keygen failed".into()))?;

    Ok(DsaKeypair {
        public_key: DsaPublicKey(pk.into_bytes().to_vec()),
        secret_key: DsaSecretKey(sk.into_bytes().to_vec()),
    })
}

pub fn dsa_sign(secret_key: &DsaSecretKey, message: &[u8]) -> Result<DsaSignature> {
    let sk_bytes: [u8; DSA_SECRET_KEY_LEN] = secret_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Encryption("invalid DSA secret key length".into()))?;

    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|_| OinError::Encryption("invalid ML-DSA secret key".into()))?;

    let sig = sk.try_sign(message, &[])
        .map_err(|_| OinError::Encryption("ML-DSA signing failed".into()))?;

    Ok(DsaSignature(sig.to_vec()))
}

pub fn dsa_verify(public_key: &DsaPublicKey, message: &[u8], signature: &DsaSignature) -> Result<bool> {
    let pk_bytes: [u8; DSA_PUBLIC_KEY_LEN] = public_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid DSA public key length".into()))?;

    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|_| OinError::Decryption("invalid ML-DSA public key".into()))?;

    let sig_bytes: [u8; DSA_SIGNATURE_LEN] = signature.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid DSA signature length".into()))?;

    Ok(pk.verify(message, &sig_bytes, &[]))
}

pub fn slh_keygen() -> Result<SlhKeypair> {
    let (pk, sk) = slh_dsa_shake_256s::try_keygen()
        .map_err(|_| OinError::Encryption("SLH-DSA-SHAKE-256s keygen failed".into()))?;

    Ok(SlhKeypair {
        public_key: SlhPublicKey(pk.into_bytes().to_vec()),
        secret_key: SlhSecretKey(sk.into_bytes().to_vec()),
    })
}

pub fn slh_sign(secret_key: &SlhSecretKey, message: &[u8]) -> Result<SlhSignature> {
    let sk_bytes: [u8; SLH_SECRET_KEY_LEN] = secret_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Encryption("invalid SLH secret key length".into()))?;

    let sk = slh_dsa_shake_256s::PrivateKey::try_from_bytes(&sk_bytes)
        .map_err(|_| OinError::Encryption("invalid SLH-DSA secret key".into()))?;

    let sig = sk.try_sign(message, b"oin:slh-dsa", true)
        .map_err(|_| OinError::Encryption("SLH-DSA signing failed".into()))?;

    Ok(SlhSignature(sig.to_vec()))
}

pub fn slh_verify(public_key: &SlhPublicKey, message: &[u8], signature: &SlhSignature) -> Result<bool> {
    let pk_bytes: [u8; SLH_PUBLIC_KEY_LEN] = public_key.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid SLH public key length".into()))?;

    let pk = slh_dsa_shake_256s::PublicKey::try_from_bytes(&pk_bytes)
        .map_err(|_| OinError::Decryption("invalid SLH-DSA public key".into()))?;

    let sig_bytes: &[u8; SLH_SIGNATURE_LEN] = signature.0
        .as_slice()
        .try_into()
        .map_err(|_| OinError::Decryption("invalid SLH signature length".into()))?;

    Ok(pk.verify(message, sig_bytes, b"oin:slh-dsa"))
}

pub fn dual_keygen() -> Result<DualSigningKeys> {
    Ok(DualSigningKeys {
        dsa: dsa_keygen()?,
        slh: slh_keygen()?,
    })
}

pub fn dual_verify_keys(keys: &DualSigningKeys) -> DualVerifyKeys {
    DualVerifyKeys {
        dsa_pk: keys.dsa.public_key.clone(),
        slh_pk: keys.slh.public_key.clone(),
    }
}

fn derive_hybrid_key(kem_secret: &[u8; 32], classical_key: &[u8; 32]) -> DataKey {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(kem_secret);
    ikm[32..].copy_from_slice(classical_key);

    let hk = Hkdf::<Sha3_256>::new(Some(b"oin:pqc:hybrid:v1"), &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"oin:hybrid-aes-key", &mut okm)
        .expect("HKDF-SHA3 expand should not fail with 32-byte output");
    DataKey(okm)
}

fn envelope_signable(env: &PqcEnvelope) -> Result<Vec<u8>> {
    serde_json::to_vec(&(&env.version, &env.kem_ciphertext, &env.sealed))
        .map_err(|e| OinError::Encryption(format!("serialize for signing: {}", e)))
}

pub fn hybrid_encrypt(
    encaps_key: &KemEncapsKey,
    plaintext: &[u8],
    signing_key: Option<&DsaSecretKey>,
) -> Result<(PqcEnvelope, [u8; 32])> {
    let mut classical_key = [0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut classical_key);

    let (kem_ct, kem_secret) = kem_encapsulate(encaps_key)?;
    let hybrid_key = derive_hybrid_key(&kem_secret, &classical_key);
    let sealed = crypto::encrypt(&hybrid_key, plaintext)?;

    let mut envelope = PqcEnvelope {
        version: 2,
        kem_ciphertext: kem_ct,
        sealed,
        signature: None,
        slh_signature: None,
    };

    if let Some(sk) = signing_key {
        let data = envelope_signable(&envelope)?;
        envelope.signature = Some(dsa_sign(sk, &data)?);
    }

    Ok((envelope, classical_key))
}

pub fn hybrid_encrypt_dual(
    encaps_key: &KemEncapsKey,
    plaintext: &[u8],
    signing_keys: &DualSigningKeys,
) -> Result<(PqcEnvelope, [u8; 32])> {
    let mut classical_key = [0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut classical_key);

    let (kem_ct, kem_secret) = kem_encapsulate(encaps_key)?;
    let hybrid_key = derive_hybrid_key(&kem_secret, &classical_key);
    let sealed = crypto::encrypt(&hybrid_key, plaintext)?;

    let mut envelope = PqcEnvelope {
        version: 2,
        kem_ciphertext: kem_ct,
        sealed,
        signature: None,
        slh_signature: None,
    };

    let data = envelope_signable(&envelope)?;
    envelope.signature = Some(dsa_sign(&signing_keys.dsa.secret_key, &data)?);
    envelope.slh_signature = Some(slh_sign(&signing_keys.slh.secret_key, &data)?);

    Ok((envelope, classical_key))
}

pub fn hybrid_decrypt(
    decaps_key: &KemDecapsKey,
    classical_key: &[u8; 32],
    envelope: &PqcEnvelope,
    verify_key: Option<&DsaPublicKey>,
) -> Result<Vec<u8>> {
    hybrid_decrypt_dual(decaps_key, classical_key, envelope, verify_key, None)
}

pub fn hybrid_decrypt_dual(
    decaps_key: &KemDecapsKey,
    classical_key: &[u8; 32],
    envelope: &PqcEnvelope,
    dsa_verify_key: Option<&DsaPublicKey>,
    slh_verify_key: Option<&SlhPublicKey>,
) -> Result<Vec<u8>> {
    if envelope.version != 1 && envelope.version != 2 {
        return Err(OinError::Decryption(format!("unknown PQC envelope version: {}", envelope.version)));
    }

    let signable = serde_json::to_vec(&(&envelope.version, &envelope.kem_ciphertext, &envelope.sealed))
        .map_err(|e| OinError::Decryption(format!("serialize for verify: {}", e)))?;

    if let (Some(sig), Some(pk)) = (&envelope.signature, dsa_verify_key) {
        if !dsa_verify(pk, &signable, sig)? {
            return Err(OinError::Decryption("ML-DSA-87 signature verification failed".into()));
        }
    }

    if let (Some(sig), Some(pk)) = (&envelope.slh_signature, slh_verify_key) {
        if !slh_verify(pk, &signable, sig)? {
            return Err(OinError::Decryption("SLH-DSA-SHAKE-256s signature verification failed".into()));
        }
    }

    let kem_secret = kem_decapsulate(decaps_key, &envelope.kem_ciphertext)?;
    let hybrid_key = derive_hybrid_key(&kem_secret, classical_key);
    crypto::decrypt(&hybrid_key, &envelope.sealed)
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = kem_keygen().unwrap();
        let (ct, secret_1) = kem_encapsulate(&kp.encaps_key).unwrap();
        let secret_2 = kem_decapsulate(&kp.decaps_key, &ct).unwrap();
        assert_eq!(secret_1, secret_2);
    }

    #[test]
    fn kem_wrong_key_fails() {
        let kp1 = kem_keygen().unwrap();
        let kp2 = kem_keygen().unwrap();
        let (ct, secret_1) = kem_encapsulate(&kp1.encaps_key).unwrap();
        let secret_2 = kem_decapsulate(&kp2.decaps_key, &ct).unwrap();
        assert_ne!(secret_1, secret_2);
    }

    #[test]
    fn dsa_sign_verify() {
        let kp = dsa_keygen().unwrap();
        let msg = b"OIN manifest integrity check";
        let sig = dsa_sign(&kp.secret_key, msg).unwrap();
        assert!(dsa_verify(&kp.public_key, msg, &sig).unwrap());
    }

    #[test]
    fn dsa_wrong_message_fails() {
        let kp = dsa_keygen().unwrap();
        let sig = dsa_sign(&kp.secret_key, b"correct message").unwrap();
        assert!(!dsa_verify(&kp.public_key, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn dsa_wrong_key_fails() {
        let kp1 = dsa_keygen().unwrap();
        let kp2 = dsa_keygen().unwrap();
        let msg = b"test message";
        let sig = dsa_sign(&kp1.secret_key, msg).unwrap();
        assert!(!dsa_verify(&kp2.public_key, msg, &sig).unwrap());
    }

    #[test]
    fn slh_sign_verify() {
        let kp = slh_keygen().unwrap();
        let msg = b"hash-based quantum-safe signature";
        let sig = slh_sign(&kp.secret_key, msg).unwrap();
        assert!(slh_verify(&kp.public_key, msg, &sig).unwrap());
    }

    #[test]
    fn slh_wrong_message_fails() {
        let kp = slh_keygen().unwrap();
        let sig = slh_sign(&kp.secret_key, b"correct").unwrap();
        assert!(!slh_verify(&kp.public_key, b"wrong", &sig).unwrap());
    }

    #[test]
    fn slh_wrong_key_fails() {
        let kp1 = slh_keygen().unwrap();
        let kp2 = slh_keygen().unwrap();
        let msg = b"test";
        let sig = slh_sign(&kp1.secret_key, msg).unwrap();
        assert!(!slh_verify(&kp2.public_key, msg, &sig).unwrap());
    }

    #[test]
    fn slh_key_sizes() {
        let kp = slh_keygen().unwrap();
        assert_eq!(kp.public_key.0.len(), SLH_PUBLIC_KEY_LEN);
        assert_eq!(kp.secret_key.0.len(), SLH_SECRET_KEY_LEN);
    }

    #[test]
    fn slh_signature_size() {
        let kp = slh_keygen().unwrap();
        let sig = slh_sign(&kp.secret_key, b"size check").unwrap();
        assert_eq!(sig.0.len(), SLH_SIGNATURE_LEN);
    }

    #[test]
    fn hybrid_encrypt_decrypt_roundtrip() {
        let kem_kp = kem_keygen().unwrap();
        let plaintext = b"quantum-safe image data for OIN";

        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, plaintext, None,
        ).unwrap();

        let decrypted = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, None,
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn hybrid_with_dsa_signature() {
        let kem_kp = kem_keygen().unwrap();
        let dsa_kp = dsa_keygen().unwrap();
        let plaintext = b"signed quantum-safe data";

        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, plaintext, Some(&dsa_kp.secret_key),
        ).unwrap();

        assert!(envelope.signature.is_some());
        assert!(envelope.slh_signature.is_none());

        let decrypted = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, Some(&dsa_kp.public_key),
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn hybrid_dual_signature_roundtrip() {
        let kem_kp = kem_keygen().unwrap();
        let dual_keys = dual_keygen().unwrap();
        let verify_keys = dual_verify_keys(&dual_keys);
        let plaintext = b"dual-signed quantum-safe data";

        let (envelope, classical_key) = hybrid_encrypt_dual(
            &kem_kp.encaps_key, plaintext, &dual_keys,
        ).unwrap();

        assert!(envelope.signature.is_some());
        assert!(envelope.slh_signature.is_some());

        let decrypted = hybrid_decrypt_dual(
            &kem_kp.decaps_key, &classical_key, &envelope,
            Some(&verify_keys.dsa_pk), Some(&verify_keys.slh_pk),
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn dual_signature_wrong_dsa_key_fails() {
        let kem_kp = kem_keygen().unwrap();
        let dual_keys = dual_keygen().unwrap();
        let wrong_dsa = dsa_keygen().unwrap();
        let plaintext = b"tamper test dsa";

        let (envelope, classical_key) = hybrid_encrypt_dual(
            &kem_kp.encaps_key, plaintext, &dual_keys,
        ).unwrap();

        let result = hybrid_decrypt_dual(
            &kem_kp.decaps_key, &classical_key, &envelope,
            Some(&wrong_dsa.public_key), Some(&dual_keys.slh.public_key),
        );
        assert!(result.is_err());
    }

    #[test]
    fn dual_signature_wrong_slh_key_fails() {
        let kem_kp = kem_keygen().unwrap();
        let dual_keys = dual_keygen().unwrap();
        let wrong_slh = slh_keygen().unwrap();
        let plaintext = b"tamper test slh";

        let (envelope, classical_key) = hybrid_encrypt_dual(
            &kem_kp.encaps_key, plaintext, &dual_keys,
        ).unwrap();

        let result = hybrid_decrypt_dual(
            &kem_kp.decaps_key, &classical_key, &envelope,
            Some(&dual_keys.dsa.public_key), Some(&wrong_slh.public_key),
        );
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_tampered_dsa_signature_fails() {
        let kem_kp = kem_keygen().unwrap();
        let dsa_kp1 = dsa_keygen().unwrap();
        let dsa_kp2 = dsa_keygen().unwrap();
        let plaintext = b"tamper test";

        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, plaintext, Some(&dsa_kp1.secret_key),
        ).unwrap();

        let result = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, Some(&dsa_kp2.public_key),
        );
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_wrong_kem_key_fails() {
        let kem_kp1 = kem_keygen().unwrap();
        let kem_kp2 = kem_keygen().unwrap();
        let plaintext = b"wrong key test";

        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp1.encaps_key, plaintext, None,
        ).unwrap();

        let result = hybrid_decrypt(
            &kem_kp2.decaps_key, &classical_key, &envelope, None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_wrong_classical_key_fails() {
        let kem_kp = kem_keygen().unwrap();
        let plaintext = b"wrong classical key test";

        let (envelope, _) = hybrid_encrypt(
            &kem_kp.encaps_key, plaintext, None,
        ).unwrap();

        let wrong_key = [0xffu8; 32];
        let result = hybrid_decrypt(
            &kem_kp.decaps_key, &wrong_key, &envelope, None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_large_data() {
        let kem_kp = kem_keygen().unwrap();
        let mut plaintext = vec![0u8; 2 * 1024 * 1024];
        aes_gcm::aead::OsRng.fill_bytes(&mut plaintext);

        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, &plaintext, None,
        ).unwrap();

        let decrypted = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, None,
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn sha3_deterministic() {
        let h1 = sha3_256(b"test data");
        let h2 = sha3_256(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha3_different_input() {
        let h1 = sha3_256(b"data a");
        let h2 = sha3_256(b"data b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn kem_key_sizes() {
        let kem_kp = kem_keygen().unwrap();
        assert_eq!(kem_kp.encaps_key.0.len(), KEM_ENCAPS_KEY_LEN);
        assert_eq!(kem_kp.decaps_key.0.len(), KEM_DECAPS_KEY_LEN);
    }

    #[test]
    fn dsa_key_sizes() {
        let dsa_kp = dsa_keygen().unwrap();
        assert_eq!(dsa_kp.public_key.0.len(), DSA_PUBLIC_KEY_LEN);
        assert_eq!(dsa_kp.secret_key.0.len(), DSA_SECRET_KEY_LEN);
    }

    #[test]
    fn dsa_signature_size() {
        let kp = dsa_keygen().unwrap();
        let sig = dsa_sign(&kp.secret_key, b"test").unwrap();
        assert_eq!(sig.0.len(), DSA_SIGNATURE_LEN);
    }

    #[test]
    fn dual_keygen_produces_both() {
        let keys = dual_keygen().unwrap();
        assert_eq!(keys.dsa.public_key.0.len(), DSA_PUBLIC_KEY_LEN);
        assert_eq!(keys.slh.public_key.0.len(), SLH_PUBLIC_KEY_LEN);
        let vk = dual_verify_keys(&keys);
        assert_eq!(vk.dsa_pk.0.len(), DSA_PUBLIC_KEY_LEN);
        assert_eq!(vk.slh_pk.0.len(), SLH_PUBLIC_KEY_LEN);
    }

    #[test]
    fn envelope_version_2() {
        let kem_kp = kem_keygen().unwrap();
        let (envelope, _) = hybrid_encrypt(
            &kem_kp.encaps_key, b"test", None,
        ).unwrap();
        assert_eq!(envelope.version, 2);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let kem_kp = kem_keygen().unwrap();
        let (envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, b"", None,
        ).unwrap();
        let decrypted = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, None,
        ).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn truncated_kem_encaps_key_rejected() {
        let short_key = KemEncapsKey(vec![0u8; 100]);
        assert!(kem_encapsulate(&short_key).is_err());
    }

    #[test]
    fn truncated_kem_decaps_key_rejected() {
        let kem_kp = kem_keygen().unwrap();
        let (ct, _) = kem_encapsulate(&kem_kp.encaps_key).unwrap();
        let short_dk = KemDecapsKey(vec![0u8; 100]);
        assert!(kem_decapsulate(&short_dk, &ct).is_err());
    }

    #[test]
    fn truncated_kem_ciphertext_rejected() {
        let kem_kp = kem_keygen().unwrap();
        let short_ct = KemCiphertext(vec![0u8; 100]);
        assert!(kem_decapsulate(&kem_kp.decaps_key, &short_ct).is_err());
    }

    #[test]
    fn truncated_dsa_secret_key_rejected() {
        let short_sk = DsaSecretKey(vec![0u8; 100]);
        assert!(dsa_sign(&short_sk, b"test").is_err());
    }

    #[test]
    fn truncated_dsa_public_key_rejected() {
        let short_pk = DsaPublicKey(vec![0u8; 100]);
        let kp = dsa_keygen().unwrap();
        let sig = dsa_sign(&kp.secret_key, b"test").unwrap();
        assert!(dsa_verify(&short_pk, b"test", &sig).is_err());
    }

    #[test]
    fn truncated_dsa_signature_rejected() {
        let kp = dsa_keygen().unwrap();
        let short_sig = DsaSignature(vec![0u8; 100]);
        assert!(dsa_verify(&kp.public_key, b"test", &short_sig).is_err());
    }

    #[test]
    fn truncated_slh_secret_key_rejected() {
        let short_sk = SlhSecretKey(vec![0u8; 10]);
        assert!(slh_sign(&short_sk, b"test").is_err());
    }

    #[test]
    fn truncated_slh_public_key_rejected() {
        let short_pk = SlhPublicKey(vec![0u8; 10]);
        let kp = slh_keygen().unwrap();
        let sig = slh_sign(&kp.secret_key, b"test").unwrap();
        assert!(slh_verify(&short_pk, b"test", &sig).is_err());
    }

    #[test]
    fn truncated_slh_signature_rejected() {
        let kp = slh_keygen().unwrap();
        let short_sig = SlhSignature(vec![0u8; 100]);
        assert!(slh_verify(&kp.public_key, b"test", &short_sig).is_err());
    }

    #[test]
    fn bad_envelope_version_rejected() {
        let kem_kp = kem_keygen().unwrap();
        let (mut envelope, classical_key) = hybrid_encrypt(
            &kem_kp.encaps_key, b"test", None,
        ).unwrap();
        envelope.version = 99;
        let result = hybrid_decrypt(
            &kem_kp.decaps_key, &classical_key, &envelope, None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn envelope_serialization_roundtrip() {
        let kem_kp = kem_keygen().unwrap();
        let dual_keys = dual_keygen().unwrap();
        let (envelope, _) = hybrid_encrypt_dual(
            &kem_kp.encaps_key, b"serialize test", &dual_keys,
        ).unwrap();
        let json = serde_json::to_vec(&envelope).unwrap();
        let parsed: PqcEnvelope = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.version, envelope.version);
        assert_eq!(parsed.kem_ciphertext.0.len(), envelope.kem_ciphertext.0.len());
        assert!(parsed.signature.is_some());
        assert!(parsed.slh_signature.is_some());
    }

    #[test]
    fn hybrid_key_derivation_different_classical_keys() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let kem_secret = [0u8; 32];
        let key_a = derive_hybrid_key(&kem_secret, &a);
        let key_b = derive_hybrid_key(&kem_secret, &b);
        assert_ne!(key_a.0, key_b.0);
    }

    #[test]
    fn hybrid_key_derivation_different_kem_secrets() {
        let classical = [0u8; 32];
        let kem_a = [1u8; 32];
        let kem_b = [2u8; 32];
        let key_a = derive_hybrid_key(&kem_a, &classical);
        let key_b = derive_hybrid_key(&kem_b, &classical);
        assert_ne!(key_a.0, key_b.0);
    }

    #[test]
    fn dual_keys_serialization_roundtrip() {
        let keys = dual_keygen().unwrap();
        let json = serde_json::to_vec(&keys).unwrap();
        let parsed: DualSigningKeys = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.dsa.public_key.0.len(), DSA_PUBLIC_KEY_LEN);
        assert_eq!(parsed.slh.public_key.0.len(), SLH_PUBLIC_KEY_LEN);
    }
}
