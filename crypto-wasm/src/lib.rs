#![allow(deprecated)] // ExpandedKeyEncoding::from_expanded_bytes: noble returns 2400-byte NIST dk, not a 64-byte seed

use wasm_bindgen::prelude::*;
use ml_kem::{
    MlKem768, EncapsulationKey768, DecapsulationKey768,
    ExpandedDecapsulationKey, ExpandedKeyEncoding,
    kem::{Encapsulate, Decapsulate, Key, TryKeyInit, SharedKey},
    ml_kem_768::Ciphertext as Ciphertext768,
    array::Array,
};
use p256::{
    ecdh::EphemeralSecret,
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce, aead::{Aead, KeyInit as AesKeyInit, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;
use rand_core::OsRng;

const INFO: &[u8] = b"paramant-v2";
const BLOCK: usize = 5 * 1024 * 1024;

// Wire-format magic byte. 0x02 = legacy v0 (no AAD). 0x03 = current (AAD-bound).
// decrypt_blob accepts both. encrypt_blob always produces 0x03.
const MAGIC_LEGACY: u8 = 0x02;
const MAGIC_AAD:    u8 = 0x03;

fn hkdf_aes_key(ss_kem: &[u8], ss_ecdh: &[u8], salt: &[u8]) -> Result<[u8; 32], JsValue> {
    let mut ikm = Vec::with_capacity(ss_kem.len() + ss_ecdh.len());
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(ss_ecdh);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    hk.expand(INFO, &mut key).map_err(|_| JsValue::from_str("HKDF expand failed"))?;
    Ok(key)
}

/// Encrypt plaintext for a receiver identified by kem_pub (1184 B) and ecdh_pub (65 B).
/// Returns a 5 MB padded blob in wire format:
///   0x03 | u32be(ctKemLen) | ctKem | u32be(senderPubLen) | senderPub | nonce(12) | u32be(ctLen) | ct
/// All bytes from offset 0 through and including u32be(ctLen) are passed to AES-256-GCM
/// as Associated Data so any tampering with wire metadata fails verification explicitly,
/// rather than relying on cascade failure via HKDF salt = ctKem[..32].
#[wasm_bindgen]
pub fn encrypt_blob(plaintext: &[u8], kem_pub: &[u8], ecdh_pub: &[u8]) -> Result<Vec<u8>, JsValue> {
    // ML-KEM-768 encapsulate
    let ek_key: Key<EncapsulationKey768> = Array::try_from(kem_pub)
        .map_err(|_| JsValue::from_str("kem_pub must be 1184 bytes"))?;
    let ek = EncapsulationKey768::new(&ek_key)
        .map_err(|_| JsValue::from_str("invalid ML-KEM-768 public key"))?;
    let (ct_kem, ss_kem): (Ciphertext768, SharedKey<MlKem768>) = ek.encapsulate();
    let ct_kem_bytes = ct_kem.as_slice();
    let ss_kem_bytes = ss_kem.as_slice();

    // ECDH P-256 ephemeral
    let sender_secret = EphemeralSecret::random(&mut OsRng);
    let sender_pub    = P256PublicKey::from(&sender_secret);
    let sender_pub_ep = sender_pub.to_encoded_point(false);
    let sender_pub_raw: &[u8] = sender_pub_ep.as_bytes(); // 65 bytes uncompressed

    let recv_pub    = P256PublicKey::from_sec1_bytes(ecdh_pub)
        .map_err(|_| JsValue::from_str("invalid ECDH P-256 public key"))?;
    let ss_ecdh     = sender_secret.diffie_hellman(&recv_pub);
    let ss_ecdh_bytes = ss_ecdh.raw_secret_bytes();

    // HKDF-SHA256 → AES-256-GCM key  (salt = ctKem[..32], matches JS)
    let aes_key = hkdf_aes_key(ss_kem_bytes, ss_ecdh_bytes.as_ref(), &ct_kem_bytes[..32])?;

    // Build the wire-format prelude (everything from magic byte through u32be(ctLen)).
    // This is the AES-GCM Associated Data: it commits the AEAD tag to every structural
    // field of the blob, so any in-flight mutation fails with a clean auth error.
    let ct_len_u32 = u32::try_from(plaintext.len() + 16) // +16 for AES-GCM tag
        .map_err(|_| JsValue::from_str("plaintext too large for u32 length prefix"))?;
    let mut aad = Vec::with_capacity(
        1 + 4 + ct_kem_bytes.len() + 4 + sender_pub_raw.len() + 12 + 4,
    );
    aad.push(MAGIC_AAD);
    aad.extend_from_slice(&(ct_kem_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(ct_kem_bytes);
    aad.extend_from_slice(&(sender_pub_raw.len() as u32).to_be_bytes());
    aad.extend_from_slice(sender_pub_raw);
    let mut nonce_buf = [0u8; 12];
    getrandom::getrandom(&mut nonce_buf).map_err(|e| JsValue::from_str(&e.to_string()))?;
    aad.extend_from_slice(&nonce_buf);
    aad.extend_from_slice(&ct_len_u32.to_be_bytes());

    // AES-256-GCM encrypt with AAD
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&aes_key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_buf), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| JsValue::from_str("AES-GCM encrypt failed"))?;
    if ct.len() as u32 != ct_len_u32 {
        return Err(JsValue::from_str("AES-GCM produced unexpected ciphertext length"));
    }

    // Wire packet — prelude (== AAD) followed by the AEAD ciphertext+tag
    let mut pkt = Vec::with_capacity(aad.len() + ct.len());
    pkt.extend_from_slice(&aad);
    pkt.extend_from_slice(&ct);

    // Pad to 5 MB with random bytes
    let mut padded = vec![0u8; BLOCK];
    let copy = pkt.len().min(BLOCK);
    padded[..copy].copy_from_slice(&pkt[..copy]);
    if copy < BLOCK {
        getrandom::getrandom(&mut padded[copy..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    }
    Ok(padded)
}

/// Decrypt a blob produced by encrypt_blob.
///
/// kem_priv  : 2400-byte ML-KEM-768 secret key as returned by noble-post-quantum
///             ml_kem768.keygen() — NIST FIPS 203: dkPKE ∥ ek ∥ H(ek) ∥ z
/// ecdh_priv : 32-byte P-256 scalar (big-endian, raw private key bytes)
#[wasm_bindgen]
pub fn decrypt_blob(ciphertext: &[u8], kem_priv: &[u8], ecdh_priv: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ciphertext.is_empty() {
        return Err(JsValue::from_str("empty ciphertext"));
    }
    let magic = ciphertext[0];
    let aad_bound = match magic {
        MAGIC_AAD    => true,
        MAGIC_LEGACY => false,
        _ => return Err(JsValue::from_str("unexpected packet magic (expected 0x02 or 0x03)")),
    };
    let mut off = 1usize;

    macro_rules! rd_u32 {
        () => {{
            if off + 4 > ciphertext.len() { return Err(JsValue::from_str("packet truncated")); }
            let v = u32::from_be_bytes(ciphertext[off..off+4].try_into().unwrap()) as usize;
            off += 4; v
        }};
    }
    macro_rules! rd_slice {
        ($n:expr) => {{
            let n: usize = $n;
            if off + n > ciphertext.len() { return Err(JsValue::from_str("packet truncated")); }
            let s = &ciphertext[off..off+n]; off += n; s
        }};
    }

    let ct_kem_len = rd_u32!(); let ct_kem     = rd_slice!(ct_kem_len);
    let sender_len = rd_u32!(); let sender_raw  = rd_slice!(sender_len);
    let nonce      = rd_slice!(12);
    let ct_off_before_len = off;
    let ct_len     = rd_u32!(); let ct          = rd_slice!(ct_len);

    // ML-KEM-768 decapsulate — load noble's 2400-byte NIST expanded dk
    let dk_arr: ExpandedDecapsulationKey<MlKem768> = Array::try_from(kem_priv)
        .map_err(|_| JsValue::from_str("kem_priv must be 2400 bytes"))?;
    let dk = DecapsulationKey768::from_expanded_bytes(&dk_arr)
        .map_err(|_| JsValue::from_str("invalid ML-KEM-768 secret key"))?;
    let ss_kem_arr = dk
        .decapsulate_slice(ct_kem)
        .map_err(|_| JsValue::from_str("ML-KEM-768 decapsulate: wrong ciphertext length"))?;

    // ECDH P-256
    let recv_priv  = P256SecretKey::from_slice(ecdh_priv)
        .map_err(|_| JsValue::from_str("invalid ECDH P-256 private key"))?;
    let sender_pub = P256PublicKey::from_sec1_bytes(sender_raw)
        .map_err(|_| JsValue::from_str("invalid sender ECDH public key"))?;
    let ss_ecdh    = p256::ecdh::diffie_hellman(recv_priv.to_nonzero_scalar(), sender_pub.as_affine());

    // HKDF-SHA256 → AES-256-GCM key
    let aes_key = hkdf_aes_key(ss_kem_arr.as_slice(), ss_ecdh.raw_secret_bytes().as_ref(), &ct_kem[..32])?;

    // AES-256-GCM decrypt. For 0x03 blobs the AAD covers the entire wire prelude
    // (magic .. ctLen); for legacy 0x02 blobs no AAD is used.
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&aes_key));
    if aad_bound {
        let aad = &ciphertext[..ct_off_before_len + 4];
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| JsValue::from_str("AES-GCM decrypt failed — wrong key or corrupted data"))
    } else {
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| JsValue::from_str("AES-GCM decrypt failed — wrong key or corrupted data"))
    }
}
