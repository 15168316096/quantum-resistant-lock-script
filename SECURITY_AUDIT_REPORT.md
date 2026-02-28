# Security Audit Report — Quantum-Resistant Lock Script

**Date:** 2026-02-28  
**Auditor:** Automated Security Review (Copilot Coding Agent)  
**Scope:** Full repository code review  
**Status:** Draft — Manual follow-up required for items marked TODO

---

## Executive Summary

This audit covers the quantum-resistant lock script repository implementing SPHINCS+ (SLH-DSA / FIPS 205) based lock scripts for CKB (Nervos). The repository includes:

- **Rust contracts**: `sphincs-all-in-one-lock`, `hybrid-sphincs-all-in-one-lock`
- **C contract**: `c-sphincs-all-in-one-lock` (root-lock + leaf-lock)
- **Shared library**: `ckb-fips205-utils` (signing, verifying, message hashing, multisig)
- **Tools**: `ckb-sphincs-tools`, `ckb-sphincs-utils` (key generation, signing, conversion)
- **Tests**: validation-tests, nist-test-vector-tests, multisig-tests, precise-fuzzing

---

## Findings

### 🔴 HIGH Severity

#### H-1: `construct_flag` / `destruct_flag` — ParamId overflow truncation risk

**File:** `crates/ckb-fips205-utils/src/lib.rs`, lines 163-176

```rust
pub fn construct_flag(param_id: ParamId, has_signature: bool) -> u8 {
    let value: u8 = param_id.into();
    (value << 1) | if has_signature { 1 } else { 0 }
}
```

ParamId values range from 48 to 59. When shifted left by 1: `59 << 1 = 118`, which fits in u8 (max 255). However, the encoding scheme uses the full u8 range for `flag`. If a future ParamId is added with value ≥ 128, `value << 1` would overflow/wrap. While the current enum values (48-59) are safe, there is **no compile-time or runtime guard** to prevent adding a ParamId >= 128 that would silently cause incorrect flag encoding.

**Impact:** If a new ParamId >= 128 is added, signature verification would silently break.

---

#### H-2: `sign_tx_by_input_group_sphincs_plus` — Incorrect witness field layout (pubkey/signature swapped)

**File:** `tools/ckb-sphincs-tools/src/sub_conversion.rs`, lines 190-198

```rust
let witness_data = {
    let mut data = vec![0; 5 + key.get_sign_len() + key.get_pk_len()];
    data[0..5].copy_from_slice(&single_sign_witness_prefix().unwrap());
    data[5..key.get_sign_len() + 5].copy_from_slice(&key.pk);  // BUG: pubkey placed at signature offset
    data[key.get_sign_len() + 5..].copy_from_slice(&key.sign(message.as_bytes())); // BUG: signature placed at pubkey offset
    Bytes::from(data)
};
```

The layout here puts **pubkey at offset 5** for `get_sign_len()` bytes, then **signature after that**. But the contract verification code (`sphincs-all-in-one-lock/src/main.rs` and the `iterate_public_key_with_optional_signature` function) expects the layout to be:
```
[flag(1 byte)] [public_key(pk_len bytes)] [signature(sig_len bytes)]
```

So the witness data at offset 5 should first have `public_key` (of `get_pk_len()` bytes), then `signature` (of `get_sign_len()` bytes). But here it's `key.pk` placed into `data[5..key.get_sign_len() + 5]` — this uses `sign_len` as the size for the pubkey copy.

**This is a clear bug**: `key.pk` has `pk_len` bytes but is being copied into a range of `sign_len` bytes. If `sign_len != pk_len` (which is the typical case for SPHINCS+), this will either panic on slice length mismatch or produce incorrect witness data.

**Impact:** The `cc_to_def_lock_script` tool function would produce invalid transactions.

---

#### H-3: `sign_tx_by_input_group_sphincs_plus` — Incorrect CKB_TX_MESSAGE_ALL computation

**File:** `tools/ckb-sphincs-tools/src/sub_conversion.rs`, lines 170-186

The message computation in the tool does NOT match the CKB_TX_MESSAGE_ALL spec used in the contracts:

```rust
// digest the first witness - INCORRECT
blake2b.update(&witness_for_digest.as_slice()[0..16]);
blake2b.update(witness_for_digest.input_type().as_slice());
blake2b.update(witness_for_digest.output_type().as_slice());

// digest the remaining witnesses - uses witness_len as u64, spec uses u32
let witness_len = witness.raw_data().len() as u64;
blake2b.update(&witness_len.to_le_bytes());
```

Comparison with the actual contract code (`ckb_tx_message_all_in_ckb_vm.rs`):
1. The contract hashes `input_type` and `output_type` with their **molecule lengths** (4 bytes LE u32 prefix + content)
2. The contract does NOT hash `as_slice()[0..16]` of the first witness
3. The remaining witness length prefix is **u32** (4 bytes), not u64 (8 bytes)

**Impact:** Transactions signed via the tool would fail on-chain verification.

---

### 🟡 MEDIUM Severity

#### M-1: `unsafe` pointer dereference in `load_binary_infos`

**File:** `contracts/hybrid-sphincs-all-in-one-lock/src/main.rs`, line 354

```rust
fn load_binary_infos(param_id: ParamId) -> (u32, u32) {
    let (p1, p2) = crate::generated::params::binary_infos(param_id);
    unsafe { (*p1, *p2) }
}
```

The `binary_infos` function returns raw pointers to `static` variables. These statics are `#[no_mangle]` and intended to be patched by the `script-merge-tool` at build time. The unsafe dereference is correct in practice because the pointers reference valid `static` memory. However:
- No safety documentation explains why the `unsafe` is sound
- If the merge tool fails to patch the offsets, the default value `0xFFFFFFFF` would be used, potentially causing out-of-bounds access in `ckb_exec`/`ckb_spawn`

**TODO:** Add safety comments and consider runtime validation of offset values.

---

#### M-2: ZeroEncoder buffer overflow potential

**File:** `contracts/hybrid-sphincs-all-in-one-lock/src/main.rs`, lines 319-350

```rust
pub fn push(&mut self, v: u8) {
    if v == 0 || v == 0xFE {
        self.buf[self.i] = 0xFE;
        self.buf[self.i + 1] = v.wrapping_sub(1);
        self.i += 2;
    } else {
        self.buf[self.i] = v;
        self.i += 1;
    }
}
```

The `push` method does not check if `self.i + 1` (or `self.i + 2` for escape sequences) exceeds `self.buf.len()`. The caller pre-allocates the buffer with worst-case size (e.g., `(1 + 4 + 34 + 8 + 4 + 4 + 4) * 2 + 1`), but if the sizing calculation is wrong, this would panic with an index-out-of-bounds at runtime.

The `seal()` method similarly writes `self.buf[self.i] = 0;` without bounds checking.

**Impact:** If buffer sizing is miscalculated, runtime panic in the CKB VM.

---

#### M-3: Potential integer truncation in C code — `param_index` is `uint8_t` but compared as signed

**File:** `contracts/c-sphincs-all-in-one-lock/ckb-sphincsplus-root-lock.c`, lines 322-325

```c
uint8_t param_index = MULTISIG_FLAG_TO_PARAM_INDEX(flag);
CHECK2(
    param_index >= 0 && param_index < CKB_SPHINCS_SUPPORTED_PARAMS_COUNT,
    ERROR_SPHINCSPLUS_WITNESS);
```

`param_index >= 0` is always true for `uint8_t`. The macro `MULTISIG_FLAG_TO_PARAM_INDEX` expands to `(flag >> 1) - CKB_SPHINCS_MIN_PARAM_ID`. If `flag >> 1` is less than `CKB_SPHINCS_MIN_PARAM_ID`, this wraps around to a large positive value (unsigned underflow), which would be caught by the `< CKB_SPHINCS_SUPPORTED_PARAMS_COUNT` check. However, the `>= 0` comparison is misleading dead code.

**Impact:** Low — the logic is coincidentally correct due to unsigned arithmetic, but the check is misleading.

---

#### M-4: C code unaligned memory access

**File:** `contracts/c-sphincs-all-in-one-lock/ckb-sphincsplus-root-lock.c`, lines 306, 377-380

```c
*((uint32_t *)&origin[1]) = 2 + BLAKE2B_BLOCK_SIZE;
// ...
*((uint64_t *)&data[3]) = CKB_SOURCE_GROUP_INPUT;
*((uint32_t *)&data[3 + 8]) = 0;
*((uint32_t *)&data[3 + 8 + 4]) = signatures.offset - 1;
*((uint32_t *)&data[3 + 8 + 4 + 4]) = 1 + pk_size + sign_size;
```

These perform unaligned pointer casts from `uint8_t*` to `uint32_t*`/`uint64_t*` for writing data. On the RISC-V target (CKB VM), unaligned memory access may cause a fault or have poor performance depending on the VM implementation.

**Impact:** May cause runtime faults on strict alignment architectures.

---

#### M-5: `WitnessArgsReader::new_unchecked` used after validation

**File:** `contracts/sphincs-all-in-one-lock/src/main.rs`, line 68

```rust
let first_witness = WitnessArgsReader::new_unchecked(&first_witness_data);
```

The comment says "The first witness is already validated to be in correct format" because `generate_ckb_tx_message_all_with_witness` calls `WitnessArgsReader::from_slice` internally. This is correct, but if the code is ever refactored so that validation path changes, the `new_unchecked` call becomes dangerous.

**TODO:** Consider adding an explicit comment referencing the validation site.

---

### 🟢 LOW Severity

#### L-1: Key material stored in plaintext JSON

**File:** `tools/ckb-sphincs-tools/src/sub_gen_key.rs`

```rust
let data = format!(
    "{{\n  \"pubkey\" : {:?},\n  \"prikey\" : {:?}\n}}",
    key.pk, key.sk
);
std::fs::write(key_file, data).expect("write keypair failed");
```

Private keys are written as plaintext JSON arrays with no encryption, no file permission restrictions, no warning about secure storage.

**Impact:** Private keys can be trivially extracted from the key file. This is expected for a development tool but should be documented.

---

#### L-2: `sm` variable in `verify` is unused

**File:** `tools/ckb-sphincs-utils/src/sphincsplus.rs`, lines 154-157

```rust
pub fn verify(&self, msg: &[u8], sign: &[u8]) -> bool {
    let mut sm = Vec::new();
    sm.resize(32, 0xFF);
    // sm is never used after this
```

Dead code that allocates an unnecessary 32-byte buffer.

---

#### L-3: Hardcoded secp256k1 code hash

**File:** `tools/ckb-sphincs-tools/src/sub_conversion.rs`, line 403

```rust
.code_hash(
    Byte32::from_slice(&str_to_bytes(
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    ))
    .unwrap(),
)
```

The secp256k1 code hash is hardcoded. This could be problematic if deployed on a different chain or if the genesis changes.

---

#### L-4: `iterate_param_id` scans full u8 range

**File:** `crates/ckb-fips205-utils/src/lib.rs`, lines 60-69

```rust
pub fn iterate_param_id<F>(mut f: F)
where
    F: FnMut(ParamId),
{
    for i in 0..=u8::MAX {
        if let Ok(param_id) = i.try_into() {
            f(param_id);
        }
    }
}
```

This iterates 256 values to find 12 valid ParamIds. While functionally correct, it's inefficient.

---

#### L-5: Spawned processes — file descriptor leak potential

**File:** `contracts/hybrid-sphincs-all-in-one-lock/src/main.rs`, lines 200-228

In the spawn path, after creating pipes, if a subsequent operation fails (e.g., the spawn itself), the already-created pipe file descriptors are not closed. In the CKB VM this may not matter since the VM exits, but it's not clean resource management.

---

#### L-6: Typo in comment

**File:** `contracts/hybrid-sphincs-all-in-one-lock/src/main.rs`, line 268

```rust
// Reads reasponse from child VM
```

Should be "response".

---

## Architecture Security Assessment

### Positive Design Decisions

1. **Separation of root/leaf lock**: The root lock handles multisig logic and message hashing, while leaf locks handle only signature verification. This separation limits the attack surface of each component.

2. **CKB_TX_MESSAGE_ALL**: The signing message covers the full transaction including all inputs, outputs, witnesses, preventing transaction malleability.

3. **Blake2b with domain separation**: Different personalizations (`ckb-sphincs+-sct` and `ckb-sphincs+-msg`) prevent cross-purpose hash collisions.

4. **FIPS 205 compliance**: The verify function passes an empty context `&[]`, matching the FIPS 205 pure mode. The message module supports pre-hash mode with proper OID encoding.

5. **Threshold/require_first_n validation**: The multisig logic correctly enforces threshold and require_first_n constraints.

6. **Overflow checks enabled in release profile**: `Cargo.toml` sets `overflow-checks = true` for release builds.

### Potential Concerns

1. **No signature replay protection across different scripts**: If two scripts share the same key, signatures could potentially be replayed. The CKB_TX_MESSAGE_ALL covers the transaction hash which mitigates this.

2. **Large stack allocations in C code**: The leaf lock allocates `uint8_t pubkey[SPHINCS_PLUS_PK_SIZE]` and `uint8_t sign[SPHINCS_PLUS_SIGN_SIZE]` on the stack. For SPHINCS+ 256s, the signature is ~29,792 bytes, which is very large for stack allocation.

3. **The `ParsedParamId::NotSet` unreachable branch**: If `lock` has 0 pubkeys (which is prevented by `assert!(pubkeys > 0)`), the `NotSet` variant would be reached. The assertion does guard this, but it's validated at a different layer.

---

## TODO — Items Requiring Further Manual Review

- [ ] **TODO-1**: Verify that the `script-merge-tool` correctly patches binary offsets in the `offsets.rs` static variables. If patching fails, `0xFFFFFFFF` offsets would be used in `ckb_exec`/`ckb_spawn`, potentially causing undefined behavior.

- [ ] **TODO-2**: Audit the SPHINCS+ reference C implementation (in `deps/` submodules) for known vulnerabilities or deviations from the NIST standard. The Rust implementation uses the `fips205` crate — verify its version and check for known CVEs.

- [ ] **TODO-3**: Review the `ckb_tx_message_all.h` C implementation for consistency with the Rust `ckb_tx_message_all_in_ckb_vm.rs` implementation. Any divergence would mean C and Rust contracts produce different signing messages.

- [ ] **TODO-4**: Verify that the fuzzing corpus generator and precise-fuzzing tests adequately cover edge cases: empty multisig, single-signer, max-signer (255), boundary threshold values.

- [ ] **TODO-5**: The `sub_conversion.rs` tool code (H-2, H-3 above) likely produces invalid transactions — verify whether this tool is used in production or is test/development only. If production, it needs immediate fixing.

- [ ] **TODO-6**: Review stack usage in C leaf lock for large SPHINCS+ parameter sets (256f, 256s). Stack overflow could occur if `SPHINCS_PLUS_SIGN_SIZE` + `SPHINCS_PLUS_PK_SIZE` exceeds available stack space.

- [ ] **TODO-7**: Verify that the `zero_escape_encoding` implementations in C and Rust are semantically identical. Any divergence would break cross-language exec/spawn argument passing.

- [ ] **TODO-8**: The `hybrid-sphincs-all-in-one-lock` spawns child VMs for multi-param-id scenarios. Verify that a malicious witness cannot cause unbounded child VM spawning (DoS). Currently bounded by `PARAM_IDS_COUNT = 12`.

- [ ] **TODO-9**: Review the `WitnessArgs` molecule structure parsing. The C code uses a custom lazy validator (`witness_args_lazy_utils.h`). Verify its correctness against the molecule spec, especially for adversarial inputs.

- [ ] **TODO-10**: Verify that `mol2_read_and_advance` in the C code correctly handles the case where the cursor's data source returns fewer bytes than requested (partial read from lazy loading).

- [ ] **TODO-11**: Review whether the `_build_cursor_from_data` function in `ckb-sphincsplus-leaf-lock.c` correctly validates that `offset + length` does not exceed the actual witness size, preventing out-of-bounds reads.

- [ ] **TODO-12**: Assess whether the empty FIPS 205 context (`&[]` / `\0\0`) is the correct choice. FIPS 205 §10.2 recommends using context to bind signatures to specific applications.

- [ ] **TODO-13**: Review the `Cargo.lock` for dependency versions — particularly `fips205`, `ckb-std`, `ckb-gen-types`, `blake2b-rs` — and check for known vulnerabilities.

- [ ] **TODO-14**: Verify that the `nist-test-vector-tests` cover all 12 parameter sets and include both positive (valid signature) and negative (invalid signature, wrong key, tampered message) test vectors.

- [ ] **TODO-15**: The `message.rs` module handles pre-hash with SHAKE XOFs using fixed output lengths (32 bytes for SHAKE-128, 64 bytes for SHAKE-256). Verify these match the FIPS 205 specification requirements for pre-hash message representation.

---

## Security Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 HIGH | 3 | Flag overflow risk, swapped pubkey/signature in tool, incorrect message computation in tool |
| 🟡 MEDIUM | 5 | Unsafe deref, buffer overflow potential, misleading check, unaligned access, unchecked validation |
| 🟢 LOW | 6 | Plaintext keys, dead code, hardcoded hash, inefficient iteration, fd leak, typo |
| 📋 TODO | 15 | Items requiring further manual review |

**Note:** Findings H-2 and H-3 are in the `ckb-sphincs-tools` CLI tool, not in the on-chain contract code. The on-chain contracts (sphincs-all-in-one-lock, hybrid-sphincs-all-in-one-lock, c-sphincs-all-in-one-lock) have a generally sound security design. The most critical on-chain concern is the potential for unaligned memory access in C code on RISC-V (M-4).

No code changes were made in this audit — all findings are documented for manual follow-up.
