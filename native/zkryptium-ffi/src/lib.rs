//! C-ABI wrapper around zkryptium's BBS (BLS12-381-SHA-256) implementation.
//!
//! Every function returns 0 on success and -1 on error.
//! Variable-length outputs (proofs) are written to caller-allocated buffers;
//! the actual length is written to an `*out_len` parameter.

use std::slice;

use zkryptium::{
    bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey},
    keys::pair::KeyPair,
    schemes::{
        algorithms::BbsBls12381Sha256,
        generics::{PoKSignature, Signature},
    },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reconstruct `&[u8]` from a raw pointer + length. Returns None if ptr is null
/// when len > 0.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Decode a flat buffer of concatenated messages into `Vec<Vec<u8>>`.
///
/// Layout: `[u32 count][u32 len_0][bytes_0][u32 len_1][bytes_1]...`
/// All u32 values are little-endian.
unsafe fn decode_messages(ptr: *const u8, total_len: usize) -> Option<Vec<Vec<u8>>> {
    let buf = unsafe { as_slice(ptr, total_len)? };
    if buf.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(buf[..4].try_into().ok()?) as usize;
    let mut offset = 4usize;
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 4 > buf.len() {
            return None;
        }
        let msg_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        if offset + msg_len > buf.len() {
            return None;
        }
        messages.push(buf[offset..offset + msg_len].to_vec());
        offset += msg_len;
    }
    Some(messages)
}

/// Decode a flat buffer of u32 indices.
///
/// Layout: `[u32 count][u32 idx_0][u32 idx_1]...`
/// All u32 values are little-endian.
unsafe fn decode_indices(ptr: *const u8, total_len: usize) -> Option<Vec<usize>> {
    let buf = unsafe { as_slice(ptr, total_len)? };
    if buf.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(buf[..4].try_into().ok()?) as usize;
    if buf.len() < 4 + count * 4 {
        return None;
    }
    let mut indices = Vec::with_capacity(count);
    for i in 0..count {
        let start = 4 + i * 4;
        let idx = u32::from_le_bytes(buf[start..start + 4].try_into().ok()?) as usize;
        indices.push(idx);
    }
    Some(indices)
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a BBS key pair from input key material (IKM).
///
/// - `ikm_ptr` / `ikm_len`: input keying material (>= 32 bytes)
/// - `key_info_ptr` / `key_info_len`: optional `key_info` octet string (may be null/0;
///   empty is the spec default of an empty string)
/// - `sk_out`: pointer to 32-byte buffer for the secret key
/// - `pk_out`: pointer to 96-byte buffer for the public key
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn bbs_keygen(
    ikm_ptr: *const u8,
    ikm_len: usize,
    key_info_ptr: *const u8,
    key_info_len: usize,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> i32 {
    let result = (|| -> Option<()> {
        if sk_out.is_null() || pk_out.is_null() {
            return None;
        }
        let ikm = unsafe { as_slice(ikm_ptr, ikm_len)? };
        let key_info = unsafe { as_slice(key_info_ptr, key_info_len)? };
        let key_info_opt = if key_info.is_empty() { None } else { Some(key_info) };
        let kp = KeyPair::<BbsBls12381Sha256>::generate(ikm, key_info_opt, None).ok()?;
        let sk_bytes = kp.private_key().to_bytes();
        let pk_bytes = kp.public_key().to_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_out, 32);
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), pk_out, 96);
        }
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

/// Derive the public key from a secret key.
///
/// - `sk_ptr`: pointer to 32-byte secret key
/// - `pk_out`: pointer to 96-byte buffer for the public key
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn bbs_sk_to_pk(
    sk_ptr: *const u8,
    pk_out: *mut u8,
) -> i32 {
    let result = (|| -> Option<()> {
        if pk_out.is_null() {
            return None;
        }
        let sk_bytes = unsafe { as_slice(sk_ptr, 32)? };
        let sk = BBSplusSecretKey::from_bytes(sk_bytes).ok()?;
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), pk_out, 96);
        }
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

/// Sign an ordered set of messages.
///
/// - `sk_ptr`: 32-byte secret key
/// - `pk_ptr`: 96-byte public key
/// - `header_ptr` / `header_len`: optional header (may be null/0)
/// - `messages_ptr` / `messages_len`: encoded message buffer (see `decode_messages`)
/// - `sig_out`: pointer to 80-byte buffer for the signature
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn bbs_sign(
    sk_ptr: *const u8,
    pk_ptr: *const u8,
    header_ptr: *const u8,
    header_len: usize,
    messages_ptr: *const u8,
    messages_len: usize,
    sig_out: *mut u8,
) -> i32 {
    let result = (|| -> Option<()> {
        if sig_out.is_null() {
            return None;
        }
        let sk_bytes = unsafe { as_slice(sk_ptr, 32)? };
        let pk_bytes = unsafe { as_slice(pk_ptr, 96)? };
        let header = unsafe { as_slice(header_ptr, header_len)? };
        let messages = unsafe { decode_messages(messages_ptr, messages_len)? };

        let sk = BBSplusSecretKey::from_bytes(sk_bytes).ok()?;
        let pk = BBSplusPublicKey::from_bytes(pk_bytes).ok()?;

        let header_opt = if header.is_empty() { None } else { Some(header) };
        let msgs_opt = if messages.is_empty() { None } else { Some(messages.as_slice()) };

        let sig = Signature::<BbsBls12381Sha256>::sign(msgs_opt, &sk, &pk, header_opt).ok()?;
        let sig_bytes = sig.to_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), sig_out, 80);
        }
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

/// Verify a BBS signature against the full set of messages.
///
/// Returns 0 if valid, -1 if invalid or error.
#[no_mangle]
pub unsafe extern "C" fn bbs_verify(
    pk_ptr: *const u8,
    header_ptr: *const u8,
    header_len: usize,
    messages_ptr: *const u8,
    messages_len: usize,
    sig_ptr: *const u8,
) -> i32 {
    let result = (|| -> Option<()> {
        let pk_bytes = unsafe { as_slice(pk_ptr, 96)? };
        let header = unsafe { as_slice(header_ptr, header_len)? };
        let messages = unsafe { decode_messages(messages_ptr, messages_len)? };
        let sig_bytes = unsafe { as_slice(sig_ptr, 80)? };

        let pk = BBSplusPublicKey::from_bytes(pk_bytes).ok()?;
        let sig_arr: [u8; 80] = sig_bytes.try_into().ok()?;
        let sig = Signature::<BbsBls12381Sha256>::from_bytes(&sig_arr).ok()?;

        let header_opt = if header.is_empty() { None } else { Some(header) };
        let msgs_opt = if messages.is_empty() { None } else { Some(messages.as_slice()) };

        sig.verify(&pk, msgs_opt, header_opt).ok()?;
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

// ---------------------------------------------------------------------------
// Proof generation / verification
// ---------------------------------------------------------------------------

/// Derive a selective-disclosure proof.
///
/// - `pk_ptr`: 96-byte public key
/// - `sig_ptr`: 80-byte signature
/// - `header_ptr` / `header_len`: optional header
/// - `ph_ptr` / `ph_len`: presentation header / nonce
/// - `messages_ptr` / `messages_len`: ALL messages (encoded)
/// - `indices_ptr` / `indices_len`: disclosed indices (encoded)
/// - `proof_out`: caller-allocated buffer (must be large enough)
/// - `proof_out_cap`: capacity of proof_out in bytes
/// - `proof_out_len`: receives the actual proof length
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn bbs_proof_gen(
    pk_ptr: *const u8,
    sig_ptr: *const u8,
    header_ptr: *const u8,
    header_len: usize,
    ph_ptr: *const u8,
    ph_len: usize,
    messages_ptr: *const u8,
    messages_len: usize,
    indices_ptr: *const u8,
    indices_len: usize,
    proof_out: *mut u8,
    proof_out_cap: usize,
    proof_out_len: *mut usize,
) -> i32 {
    let result = (|| -> Option<()> {
        if proof_out.is_null() || proof_out_len.is_null() {
            return None;
        }
        let pk_bytes = unsafe { as_slice(pk_ptr, 96)? };
        let sig_bytes = unsafe { as_slice(sig_ptr, 80)? };
        let header = unsafe { as_slice(header_ptr, header_len)? };
        let ph = unsafe { as_slice(ph_ptr, ph_len)? };
        let messages = unsafe { decode_messages(messages_ptr, messages_len)? };
        let indices = unsafe { decode_indices(indices_ptr, indices_len)? };

        let pk = BBSplusPublicKey::from_bytes(pk_bytes).ok()?;

        let header_opt = if header.is_empty() { None } else { Some(header) };
        let ph_opt = if ph.is_empty() { None } else { Some(ph) };
        let msgs_opt = if messages.is_empty() { None } else { Some(messages.as_slice()) };
        let idxs_opt = if indices.is_empty() { None } else { Some(indices.as_slice()) };

        let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
            &pk, sig_bytes, header_opt, ph_opt, msgs_opt, idxs_opt,
        )
        .ok()?;

        let proof_bytes = proof.to_bytes();
        if proof_bytes.len() > proof_out_cap {
            return None; // buffer too small
        }
        unsafe {
            std::ptr::copy_nonoverlapping(proof_bytes.as_ptr(), proof_out, proof_bytes.len());
            *proof_out_len = proof_bytes.len();
        }
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

/// Verify a selective-disclosure proof.
///
/// - `pk_ptr`: 96-byte public key
/// - `proof_ptr` / `proof_len`: the proof bytes
/// - `header_ptr` / `header_len`: optional header
/// - `ph_ptr` / `ph_len`: presentation header / nonce
/// - `disclosed_msgs_ptr` / `disclosed_msgs_len`: only the DISCLOSED messages (encoded)
/// - `indices_ptr` / `indices_len`: disclosed indices (encoded)
///
/// Returns 0 if valid, -1 if invalid or error.
#[no_mangle]
pub unsafe extern "C" fn bbs_proof_verify(
    pk_ptr: *const u8,
    proof_ptr: *const u8,
    proof_len: usize,
    header_ptr: *const u8,
    header_len: usize,
    ph_ptr: *const u8,
    ph_len: usize,
    disclosed_msgs_ptr: *const u8,
    disclosed_msgs_len: usize,
    indices_ptr: *const u8,
    indices_len: usize,
) -> i32 {
    let result = (|| -> Option<()> {
        let pk_bytes = unsafe { as_slice(pk_ptr, 96)? };
        let proof_bytes = unsafe { as_slice(proof_ptr, proof_len)? };
        let header = unsafe { as_slice(header_ptr, header_len)? };
        let ph = unsafe { as_slice(ph_ptr, ph_len)? };
        let disclosed = unsafe { decode_messages(disclosed_msgs_ptr, disclosed_msgs_len)? };
        let indices = unsafe { decode_indices(indices_ptr, indices_len)? };

        let pk = BBSplusPublicKey::from_bytes(pk_bytes).ok()?;
        let proof = PoKSignature::<BbsBls12381Sha256>::from_bytes(proof_bytes).ok()?;

        let header_opt = if header.is_empty() { None } else { Some(header) };
        let ph_opt = if ph.is_empty() { None } else { Some(ph) };
        let msgs_opt = if disclosed.is_empty() { None } else { Some(disclosed.as_slice()) };
        let idxs_opt = if indices.is_empty() { None } else { Some(indices.as_slice()) };

        proof.proof_verify(&pk, msgs_opt, idxs_opt, header_opt, ph_opt).ok()?;
        Some(())
    })();
    if result.is_some() { 0 } else { -1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn encode_messages(messages: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(messages.len() as u32).to_le_bytes());
        for msg in messages {
            buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
            buf.extend_from_slice(msg);
        }
        buf
    }

    fn encode_indices(indices: &[u32]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(indices.len() as u32).to_le_bytes());
        for &idx in indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        buf
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        let ikm = [0xAAu8; 32];
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 96];

        let rc = unsafe {
            bbs_keygen(
                ikm.as_ptr(), ikm.len(),
                ptr::null(), 0,
                sk.as_mut_ptr(), pk.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);

        let messages = encode_messages(&[b"msg1", b"msg2", b"msg3"]);
        let header = b"test-header";
        let mut sig = [0u8; 80];

        let rc = unsafe {
            bbs_sign(
                sk.as_ptr(), pk.as_ptr(),
                header.as_ptr(), header.len(),
                messages.as_ptr(), messages.len(),
                sig.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);

        let rc = unsafe {
            bbs_verify(
                pk.as_ptr(),
                header.as_ptr(), header.len(),
                messages.as_ptr(), messages.len(),
                sig.as_ptr(),
            )
        };
        assert_eq!(rc, 0);
    }

    #[test]
    fn verify_wrong_message_fails() {
        let ikm = [0xBBu8; 32];
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 96];
        unsafe {
            bbs_keygen(
                ikm.as_ptr(), ikm.len(),
                ptr::null(), 0,
                sk.as_mut_ptr(), pk.as_mut_ptr(),
            )
        };

        let messages = encode_messages(&[b"msg1"]);
        let header = b"";
        let mut sig = [0u8; 80];
        unsafe {
            bbs_sign(
                sk.as_ptr(), pk.as_ptr(),
                ptr::null(), 0,
                messages.as_ptr(), messages.len(),
                sig.as_mut_ptr(),
            );
        }

        let wrong_messages = encode_messages(&[b"wrong"]);
        let rc = unsafe {
            bbs_verify(
                pk.as_ptr(),
                ptr::null(), 0,
                wrong_messages.as_ptr(), wrong_messages.len(),
                sig.as_ptr(),
            )
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn proof_gen_verify_round_trip() {
        let ikm = [0xCCu8; 32];
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 96];
        unsafe {
            bbs_keygen(
                ikm.as_ptr(), ikm.len(),
                ptr::null(), 0,
                sk.as_mut_ptr(), pk.as_mut_ptr(),
            )
        };

        let messages = encode_messages(&[b"name", b"age", b"email"]);
        let header = b"credential-header";
        let mut sig = [0u8; 80];
        let rc = unsafe {
            bbs_sign(
                sk.as_ptr(), pk.as_ptr(),
                header.as_ptr(), header.len(),
                messages.as_ptr(), messages.len(),
                sig.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);

        // Disclose only message 0 ("name") and 2 ("email")
        let indices = encode_indices(&[0, 2]);
        let ph = b"verifier-nonce";
        let mut proof_buf = [0u8; 2048];
        let mut proof_len: usize = 0;

        let rc = unsafe {
            bbs_proof_gen(
                pk.as_ptr(),
                sig.as_ptr(),
                header.as_ptr(), header.len(),
                ph.as_ptr(), ph.len(),
                messages.as_ptr(), messages.len(),
                indices.as_ptr(), indices.len(),
                proof_buf.as_mut_ptr(), proof_buf.len(),
                &mut proof_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(proof_len > 0);

        // Verify with only the disclosed messages
        let disclosed_msgs = encode_messages(&[b"name", b"email"]);
        let rc = unsafe {
            bbs_proof_verify(
                pk.as_ptr(),
                proof_buf.as_ptr(), proof_len,
                header.as_ptr(), header.len(),
                ph.as_ptr(), ph.len(),
                disclosed_msgs.as_ptr(), disclosed_msgs.len(),
                indices.as_ptr(), indices.len(),
            )
        };
        assert_eq!(rc, 0);
    }
}
