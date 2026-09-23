# Design

Decisions taken while building the verifier, and the reasoning behind each.
Compute-unit arithmetic lives in [cu-budget.md](cu-budget.md); this document
covers structure and rationale.

## 1. One program, one account per circuit

On Ethereum a Groth16 verifier is generated per circuit with the verifying key
baked into the bytecode, and the circuit's identity is the contract address.
Solana separates code from state, so that pattern has three possible analogues.

**Deploy a program per circuit.** The key becomes a `const` in the binary.
Faithful to the Ethereum model, but every circuit costs a source change, a
rebuild, and rent on a program-data account sized to the whole ELF — hundreds of
kilobytes for what is a few kilobytes of actual key material. Nothing is shared
between circuits.

**Pass the key in instruction data.** Stateless, cheapest in compute, and the
closest match to the [ed25519 program] this repository follows structurally. It
fails on identity, not on mechanics. An Ed25519 public key *is* the identity of
the signer; a Groth16 verifying key is a kilobyte of curve points whose identity
is a hash of them. A program handed those bytes cannot tell whether they are the
key the caller meant, so every caller would have to carry the expected hash,
recompute it over the full key on every verification, and compare — a check
that is the same for every circuit and every caller, repeated per transaction
instead of performed once.

Size is the secondary objection, and it depends on the transaction format. A
key body is `448 + 64·(n+1)` bytes: 1,024 bytes at `n = 8`, 10,184 at the
maximum `n = 151`. Legacy and v0 transactions are capped at 1,232 bytes, which
leaves no room for a key beyond a handful of inputs once the 256-byte proof, the
public inputs and the transaction envelope are counted. The v1 format
([SIMD-0385]) raises the cap to 4,096 bytes ([SIMD-0296]) — scheduled for
mainnet activation at epoch 1035 — so under v1 a key, proof and inputs fit in one
transaction up to roughly `n ≈ 30`. That covers many circuits but not all, it
requires the caller to adopt v1, which also drops address lookup tables and
changes how compute and priority fees are declared, and it still ships the same
kilobyte of key with every proof.

**One program, one key account per circuit.** This is what the program does.
The key lives in a PDA, written once and sealed. The PDA address plays the role
the contract address plays on Ethereum: it names the circuit, it is stable, and
it can be hardcoded by a consumer. The identity check is performed exactly once,
at `Publish`, and afterwards a caller pins a circuit by pinning 32 bytes.

The compute cost of the third option is not meaningfully worse than the second.
Pinocchio maps account data into the program's address space without copying, so
reading the key out of an account costs the same `memcpy` as reading it out of
instruction data. What the account buys is that the key's identity is checkable
and checked once, and that the proof travels alone — a `Verify` transaction
carries the 256-byte proof and `32·n` bytes of inputs and nothing else, so the
transaction-size ceiling on `n` (about 20 under the 1,232-byte limit, see
[cu-budget.md](cu-budget.md)) is set by the inputs alone and rises with the
format rather than being eaten by the key.

[ed25519 program]: https://github.com/solana-program/ed25519
[SIMD-0296]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0296-larger-transactions.md
[SIMD-0385]: https://solana.com/upgrades/larger-transaction-sizes

## 2. The address is the key's hash

PDA seeds are `[b"vk", sha256(vk_body)]`.

A key account could instead be keyed by an authority plus a circuit id, but that
introduces a question the verifier should not have to answer: who is allowed to
say what circuit `id` means, and what happens when they change their mind.
Content addressing removes it. The address commits to the bytes, `Publish`
enforces the commitment once, and the account is immutable afterwards.

What this gives a CPI caller is the property the Ethereum pattern has: pinning
one 32-byte address pins the exact verifying key, transitively. The caller does
not have to inspect the account, and the verifier does not have to prove
anything about it beyond ownership.

`Verify` therefore does *not* re-derive the PDA. Re-deriving would mean hashing
the key body and running `create_program_address` on every verification, several
thousand compute units spent re-establishing a fact the caller asserted when it
chose the address. The two checks `Verify` does make are a 32-byte comparison
of the account's owner pubkey against the program id — by value, not by
address; the runtime gives no guarantee the two live at the same location — and
a one-byte comparison on the discriminator.

The cost of immutability is that a circuit cannot be upgraded in place. That is
deliberate and matches the model being copied — on Ethereum, a new verifying key
is a new contract. Here it is a new address.

### Why the canonical account is never written in place

A key can be larger than one transaction can carry — 10,184 bytes at the
maximum `n = 151`, against 1,232 bytes for legacy and v0 transactions and 4,096
for v1 — so the upload path has to allow a key to arrive in pieces, and the
question is where those pieces accumulate. Small keys sent by a v1 client may
fit in a single `Write`, but the design has to be correct for the ones that do
not. Two designs were considered and rejected before the current one.

*Upload directly into the canonical PDA, gated on the initializer.* Whoever
calls `Initialize` first controls the account. Anyone can therefore squat a
key's canonical address — initialize it, write nothing useful, never finalize —
and nobody else can recover it. Worse, `Initialize` has to take `n` as a
parameter to size the account, so the squatter doesn't even need to write
garbage: initializing with the wrong `n` already makes the address unusable.

*Upload directly into the canonical PDA, permissionless.* Content addressing
means wrong bytes can never be sealed, so letting anyone write looks harmless.
It is not: an adversary who overwrites several earlier chunks forces the
uploader to re-send all of them alongside `Finalize`, and once the damaged
region exceeds a transaction's capacity there is no atomic recovery. Sustained
interference blocks the upload indefinitely. And the wrong-`n` squat from the
first design still applies, since only the initializer could resize or close.

*Upload into a private staging account, then publish atomically.* This is the
design. The staging account is owned by its authority and nobody else can touch
it, so there is no race. The canonical PDA is created *by* `Publish`, in the
same instruction that checks the body's hash against the address, validates
the body, sizes the account from `n`, and fills it. There is no instruction that writes
to a canonical account after that. Consequently the canonical address has
exactly two possible states — nonexistent, or complete and correct — and no
adversary can move it into a third.

It is the BPF upgradeable loader's `InitializeBuffer` / `Write` /
`DeployWithMaxDataLen` pattern, for the same reason the loader uses it.

`Write` addresses the staging *body*: `offset` is relative to byte 40, the
write must satisfy `offset + len ≤ body_len` under checked arithmetic, and the
40-byte header is unreachable. A `Write` that could reach the header could
change `authority` or `n`, and the point of the staging account is that its
authority alone controls what ends up in it.

Two more details are needed for "no adversary can affect the outcome" to be
literally true, and both are on the README's registration path:

- `Publish` cannot require the target address to be *empty*, only to be
  *unowned by the program*. Lamports can be sent to any address, and
  `create_account` refuses a funded target, so a one-lamport transfer would be a
  permanent veto on a key. `Publish` builds the account with
  `transfer`-if-short / `allocate` / `assign` instead, all signed with the PDA
  seeds, and treats a nonzero balance as free rent.
- `Publish` derives the bump itself with `find_program_address` and stores it.
  Accepting a caller-supplied bump would let one key live at several addresses
  — every valid bump for the seeds — which defeats "one key, one address".

And one that is a client obligation rather than a program check:
`create_account` and `InitializeStaging` must share a transaction, because the
program cannot tell who funded a blank account. Split across two transactions,
a third party can initialize it first and later reclaim its rent with
`CloseStaging`. Nothing worse: a hijacked staging account holds nothing of the
uploader's, and the uploader simply creates another.

The staging `authority` gates `Write`, `Publish` and `CloseStaging`. It lives
in the staging header, which is not part of the hashed body, so the canonical
address does not depend on who uploaded.

### The program must be immutable for any of this to hold

"No instruction writes to a canonical account" is a property of the deployed
code. A program with a live upgrade authority can be replaced by one that does,
or by one whose `Verify` accepts anything. The deployment plan is to revoke the
upgrade authority (`--final`), and the README says so in its trust section. A
caller integrating against a deployment that has not done that is trusting the
authority holder, and should know it.

## 3. Uncompressed, big-endian, everywhere on-chain

The syscalls consume uncompressed big-endian points. Anything else has to be
converted, and conversion on-chain is expensive in the one case that matters:
`ALT_BN128_G2_DECOMPRESS` costs 13,610 CU per point. A verifying key holds three
G2 points and a proof holds one. Accepting compressed input would add 40,830 CU
to key registration for the G2 points alone (plus 398 per G1 point for `α` and
each `ICᵢ`), and 13,610 CU for `B` plus 796 for `A` and `C` to every single
verification — roughly 18% on top of a one-public-input proof, to save 128
bytes of instruction data.

So the on-chain format is the syscall format, and `groth16-convert` does the
translation on the host:

- **gnark** serializes compressed and big-endian, with the compression flag in
  the three most significant bits of the first byte. The converter decompresses
  and emits the uncompressed form.
- **arkworks** serializes little-endian with the flag in the high bits of the
  *last* byte. The converter reverses limbs as well as decompressing.

Both paths land on the same canonical on-chain bytes, which is what makes the
gnark fixture test and the randomized arkworks test exercise the same program
code.

### Endianness of the syscall itself

SIMD-0284 added little-endian variants of every `alt_bn128` op
(`ALT_BN128_*_LE`, the base opcode with a flag bit set), gated behind the
`alt_bn128_little_endian` feature. They cost exactly the same as the big-endian
ones.

The program uses the big-endian variants. Because both the key and the proof
arrive already in syscall-native form, the program never performs a byte
reversal, so the little-endian variants would save nothing on-chain — they would
only shift work between the two host-side converters, and only for arkworks.
Choosing big-endian keeps the program working on validators regardless of
whether that feature is active.

## 4. Negate on the G2 side

The Groth16 equation is `e(A, B) = e(α, β) · e(L, γ) · e(C, δ)`. The pairing
syscall does not compute pairings and hand them back; it takes a list of pairs
and answers one question, whether the product of their pairings is one. So the
equation has to be rearranged into that form first, which means moving the
right-hand side across and negating one point in each of the three moved
pairs. Either point of a pair can carry the sign, because
`e(−P, Q) = e(P, −Q) = e(P, Q)⁻¹`. The choice is not which negation is cheaper
to compute — a G1 negation is one `Fq` subtraction and a G2 negation is two —
but *when and by whom* it is computed. The target is that the program computes
none of them.

There are three places the sign can go:

| Negate       | Equation checked                            | Negations done by the program at `Verify`       |
| ------------ | ------------------------------------------- | ----------------------------------------------- |
| G1: `α, L, C` | `e(A,B)·e(−α,β)·e(−L,γ)·e(−C,δ) = 1`       | Two. `α` can be stored negated in the key, but `L` is the MSM result computed on-chain and `C` arrives in the proof. |
| G1: `A`      | `e(−A,B)·e(α,β)·e(L,γ)·e(C,δ) = 1`          | One, unless the client submits `−A` in place of `A`. |
| G2: `β, γ, δ` | `e(A,B)·e(α,−β)·e(L,−γ)·e(C,−δ) = 1`       | None. All three are verifying-key elements.     |

The program negates the G2 side. `β`, `γ` and `δ` are fixed per circuit, so
`groth16-convert` negates them once on the host — `y ∈ Fq2` becomes
`(p − y₀, p − y₁)` — and `Publish` stores the negated points. The hot path
copies bytes into the pairing buffer and does no field arithmetic outside the
syscalls. There is no negation opcode in the `alt_bn128` syscall family, so
any negation the program did perform would be hand-written 256-bit modular
subtraction in SBF: cheap, but not free, and one more path to get right,
including the identity case where `y = 0`.

The second row deserves a word, because a client that submits `−A` also
reaches zero on-chain negations. The difference is where the transformation
lives. Negating the key happens once per circuit, at registration, and a proof
is then verified exactly as gnark or arkworks emit it. Negating `A` happens
once per proof, in every client, forever, and a proof taken straight from a
prover fails to verify with no indication why. gnark's own `VerifyingKey`
stores `gammaNeg` and `deltaNeg` for the same reason: the key is the right
place to absorb the sign, so for gnark inputs part of the work is already
done.

**Why the check is four pairs and not three.** `α` and `β` are both fixed by
the key, so `e(α, β)` is a per-circuit constant. Verifiers that run their own
pairing loop exploit that: arkworks' `prepare_verifying_key` computes the
`Fq12` element once and stores it, and verification then rearranges the
equation to

```text
e(A, B) · e(L, −γ) · e(C, −δ) = e(α, β)
```

pairs only the three proof-dependent terms, and compares the product against
the stored constant. One Miller loop fewer per verification, and no `Fq12`
arithmetic beyond a comparison.

The `alt_bn128` pairing syscall cannot do this. It accepts only points and
returns only a boolean — whether the product of the given pairs is one — so
there is no way to hand it a precomputed `e(α, β)` and no way to read the
three-pair product back out to compare. `α` and `β` therefore go in as points
and are paired again on every call. The check is four pairs.

This is a limitation of the syscall, not of the scheme. The BLS12-381 syscalls
in [SIMD-0388] return the full 576-byte target-group element, and the SDK's
`solana-bls12-381` crate already exposes it as `pairing_map`; a verifier on
that curve could store `e(α, β)` in the key account and check three pairs
against it with a byte comparison. Nothing equivalent exists or is proposed for
BN254 — [SIMD-0302] adds G2 arithmetic and [SIMD-0284] added little-endian
encodings, and neither touches the pairing output.

> **TODO.** Write a SIMD adding a BN254 pairing variant that returns the
> `Fq12` product instead of a boolean, mirroring SIMD-0388's output format.
> With it, `Publish` would store `e(α, β)` (576 bytes) alongside the key and
> `Verify` would drop to a 3-pair call plus a 576-byte comparison. That saves
> one `alt_bn128_pairing_one_pair_cost_other`, 12,121 CU, on every
> verification — about a sixth of the pairing stage, which is the dominant cost
> for every circuit below `n = 18` (see [cu-budget.md](cu-budget.md)). It is
> the largest remaining saving that does not require changing the scheme.

[SIMD-0284]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0284-alt-bn128-little-endian.md
[SIMD-0302]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0302-bn254-g2-syscalls.md
[SIMD-0388]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0388-bls12-381-syscalls.md

## 5. Assembling the pairing input

The syscall takes one contiguous `4 × 192 = 768`-byte buffer. Both the account
layout and the proof layout are chosen so that filling it is `memcpy` and
nothing else:

```text
slot 0   A ‖ B      192 bytes   one copy from instruction data
slot 1   α ‖ −β     192 bytes   one copy from the key account
slot 2   L ‖ −γ     64 + 128    L from the MSM, −γ one copy
slot 3   C ‖ −δ     64 + 128    C from instruction data, −δ one copy
```

The proof is laid out `A ‖ B ‖ C` rather than in any other order precisely so
that slot 0 is a single copy; the key is laid out `α ‖ −β ‖ −γ ‖ −δ` so that
slot 1 is. The buffer is a stack array — the program declares
`pinocchio::no_allocator!()` and never heap-allocates.

## 6. What the syscall already checks

`alt_bn128_pairing` deserializes each point through arkworks with
`Validate::Yes`, which performs both the on-curve check and the prime-order
subgroup check, and fails the syscall if either does not hold. Groth16 soundness
requires exactly those checks on `A`, `B` and `C`; the program does not repeat
them.

This is worth stating explicitly because it is the kind of thing that gets
"defensively" re-added later. Re-validating `A`, `B` and `C` in SBF would be
thousands of compute units duplicating work the syscall does unconditionally.

The verifying key's points are validated once, at `Publish`, so a malformed key
can never reach the hot path — and a key that passes `Publish` is pinned by its
address forever.

Not every `alt_bn128` opcode validates equally, and `Publish` has to pick the
ones that do. In `solana-bn254`, G1 and G2 conversions through
`TryFrom<PodG1>`/`TryFrom<PodG2>` use `Validate::Yes` — that is the pairing path
and the multiplication path. G2 *addition*, however, goes through
`into_affine_unchecked`, which checks the curve equation but explicitly skips
the subgroup check. So `Publish` must not validate `−β`, `−γ`, `−δ` with
`ALT_BN128_G2_ADD`; it validates them with one 3-pair pairing call,
`(α, −β), (IC₀, −γ), (IC₀, −δ)`, which validates all three G2 points and both
`α` and `IC₀`. `IC₀` is paired twice rather than reaching for `IC₁` because a
key with `n = 0` has no `IC₁`. The remaining `IC₁..ICₙ` go through `G1_ADD`
two at a time, an odd last point added to itself — G1 addition *does*
deserialize both operands with full validation, and
BN254's G1 has cofactor 1, so on-curve is in-subgroup. In every case the check
is that the *syscall succeeds* — a failed deserialization returns an error —
and the 32-byte pairing result is ignored: these pairs have no reason to
multiply to one for a legitimate key, and requiring it would reject every
valid key. This is the cold path, so the cost is not optimized beyond the
obvious — `IC₁..ICₙ` are validated two per `G1_ADD`, since the syscall
deserializes both operands; it comes to `61,299 + 334·⌈n/2⌉` plus fixed
overhead, and stays inside the default budget for every publishable `n`. See [cu-budget.md § Publish](cu-budget.md#publish).

## 7. Crate split

`solana-groth16-verify` is `no_std` with no allocator on the verification path and no
dependency on Solana runtime error types. Its error type is a plain enum, as in
the ed25519 program's `Ed25519VerifyError`, so a consumer outside a Solana
program is not forced into `ProgramError`. A program that wants to verify inline
rather than via CPI depends on this crate and calls it directly; the SBF program
is a thin dispatcher on top.

`groth16-convert` is a separate crate rather than a feature because it pulls in
`ark-bn254`, `ark-serialize` and `gnark`-format parsing — heavy `std`
dependencies that have no business being reachable, even behind a disabled
feature flag, from the crate that gets compiled into an SBF artifact. It lives
under `tools/` with the bench program and the gnark fixture: the two crates a
consumer depends on are the verifier and the program, and everything under
`tools/` exists to produce, convert or measure inputs to them.

The client-side instruction builders stay in `solana-groth16-verify` behind an
`instruction` feature, matching the ed25519 program's arrangement, so a pure
client can build transactions without pulling in either the syscall wrappers or
the converters.

## 8. Error model

`Groth16Error` distinguishes the failure modes the caller can act on:
malformed proof or key encoding, a public-input count that doesn't match the
key, a non-canonical field element, a key account that isn't finalized or isn't
owned by the program, and — separately from all of those — a well-formed proof
that does not satisfy the equation.

The program carries every one of them across its boundary as
`ProgramError::Custom(code)`, one code per variant, so a CPI caller sees the
same distinctions a direct library consumer does. Failures the registry itself
detects (wrong address, already published, staging size, write bounds,
identity element) have codes of their own from 100 up, and plain account and
signature failures use the standard `ProgramError` variants. `program/src/error.rs`
is the table.

## 9. Eager entrypoint, not lazy

Pinocchio offers two entrypoints. The lazy one hands the program an
`InstructionContext` and parses accounts one at a time on demand, which is
the cheaper choice when a program knows up front how many accounts it takes.
This program does not: the tag that decides between one account (`Verify`)
and five (`Publish`) is the first byte of the instruction data, and the lazy
context refuses to expose the instruction data until every account has been
consumed. The first build with the lazy entrypoint compiled to a 1 KB program
that returned `InvalidInstructionData` on every path — the compiler had
correctly worked out that `instruction_data()` could never succeed with
accounts present.

The eager entrypoint (`program_entrypoint!`, capped at five accounts) parses
whatever accounts were passed and hands over `(program_id, accounts, data)`.
For `Verify` that is one account, and the measured cost of all account
handling on that path is 52 CU, so nothing was lost.

## 10. Edge cases to pin down in tests

These are all cheap to get wrong and cheap to test, so they get explicit
coverage rather than reasoning:

- **Point at infinity.** The syscalls encode the identity as all-zero bytes
  (`PodG1`/`PodG2::try_from` in `solana-bn254` special-case it before
  deserializing), which is *not* arkworks' own uncompressed encoding — arkworks
  uses a flag bit. The converter must map between the two. An `ICᵢ` at infinity
  is legal in a verifying key and `Publish` accepts it; `α`, `−β`, `−γ`, `−δ`
  at infinity make the equation degenerate and are rejected.
- **`L` at the identity.** `L = IC₀ + Σ aᵢ·ICᵢ` is the identity whenever the
  sum cancels, and cancellation is not exotic: `Σ aᵢ·ICᵢ = −IC₀` with all
  terms nonzero does it, as does `IC₀` itself being the identity with all
  inputs zero. Intermediate accumulator values can also pass through the
  identity even when the final `L` does not. The tests construct a synthetic
  key and inputs for each of: final `L` identity by cancellation, final `L`
  identity via zero inputs and zero `IC₀`, and an intermediate identity with a
  nonzero final `L`, checking both that the G1 add syscall handles an identity
  operand and that the pairing syscall accepts an identity in slot 2. When every
  public input is zero and `IC₀` is not the identity, `L = IC₀` — that case
  exercises the trivial-scalar skip, not identity handling.
- **Zero and one scalars.** A public input of `0` makes `aᵢ·ICᵢ` the identity
  and a public input of `1` makes it `ICᵢ`. Both are candidates for skipping the
  multiplication entirely (see [cu-budget.md](cu-budget.md)), and the `0` case
  is exactly where an identity-handling bug would surface if the skip were not
  taken.
- **Non-canonical `Fr`.** Public inputs must be `< r`. The behaviour of the G1
  multiplication syscall on an out-of-range scalar is version-dependent
  (`VersionedG1Multiplication::V1`), so the program rejects non-canonical inputs
  itself rather than depending on it.
- **`n = 0`.** A circuit with no public inputs makes `L = IC₀` with no MSM at
  all. The MSM loop must not assume at least one iteration.
- **Wrong public-input count.** Supplying `n' ≠ n` inputs must be rejected on
  the length check, never silently truncated — a verifier that ignores trailing
  public inputs is unsound.
- **Registration path.** Each of the guarantees in §2 gets a test that tries
  to break it: `Publish` onto a target that was pre-funded with one lamport;
  `Publish` where `payer` and `authority` are different keypairs (the rent
  refund lands on `authority`); `Publish` of an `n = 0` key; `Publish` of an
  `n = 151` key with the compute limit raised, confirming both the size ceiling
  and the budget estimate; `InitializeStaging` with `n = 152` (must fail); `Publish` passed
  an address derived with a non-canonical bump (must fail on the address
  check); a second `Publish` of an already-published key (must fail, leaving
  the first intact); `Write` at `offset + len` one past `body_len`, and at an
  `offset` that overflows `u32`; `InitializeStaging` on an account of the wrong
  size, and on one already initialized.
