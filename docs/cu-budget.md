# Compute-unit budget

Where the compute units go, what is fixed, and what is left to optimize.

## Syscall costs

Taken from `ComputeBudget`'s defaults in `agave/program-runtime/src/execution_budget.rs`.
These are runtime constants; nothing the program does changes them.

| Constant                                | CU     |
| --------------------------------------- | ------ |
| `alt_bn128_g1_addition_cost`            | 334    |
| `alt_bn128_g2_addition_cost`            | 535    |
| `alt_bn128_g1_multiplication_cost`      | 3,840  |
| `alt_bn128_g2_multiplication_cost`      | 15,670 |
| `alt_bn128_pairing_one_pair_cost_first` | 36,364 |
| `alt_bn128_pairing_one_pair_cost_other` | 12,121 |
| `alt_bn128_g1_decompress`               | 398    |
| `alt_bn128_g2_decompress`               | 13,610 |
| `sha256_base_cost`                      | 85     |

The G1/G2 add and multiply opcodes are charged flat — no term for input size.
The pairing opcode is not:

```text
cost = pairing_first
     + pairing_other × (pairs − 1)
     + sha256_base_cost
     + input_size
     + 32                              // output size
```

(`SyscallAltBn128` in `agave/syscalls/src/lib.rs`. Note it does not charge
`syscall_base_cost` on top.)

## The fixed floor

**Pairing**, 4 pairs, 768-byte input:

```text
36,364 + 12,121 × 3 + 85 + 768 + 32 = 73,612 CU
```

**MSM**, `L = IC₀ + Σᵢ aᵢ·ICᵢ` over `n` public inputs. There is no BN254 MSM
syscall, so this is `n` multiplications and `n` additions:

```text
n × (3,840 + 334) = 4,174n CU
```

**Core verification** is the sum:

| `n` public inputs | Pairing | MSM     | Core    | Pairing's share |
| ----------------- | ------- | ------- | ------- | --------------- |
| 0                 | 73,612  | 0       | 73,612  | 100%            |
| 1                 | 73,612  | 4,174   | 77,786  | 95%             |
| 2                 | 73,612  | 8,348   | 81,960  | 90%             |
| 4                 | 73,612  | 16,696  | 90,308  | 82%             |
| 8                 | 73,612  | 33,392  | 106,996 | 69%             |
| 16                | 73,612  | 66,784  | 140,396 | 52%             |
| 32                | 73,612  | 133,568 | 207,180 | 36%             |

The MSM overtakes the pairing at `n = 18`. Below that the pairing is the
bottleneck and it is a constant we cannot move.

## What this means for limits

Three independent limits apply, and they bind at different `n`:

| Limit                          | Binds at    | Source                                                    | Workaround                          |
| ------------------------------ | ----------- | --------------------------------------------------------- | ----------------------------------- |
| Transaction size               | `n ≈ 20`    | 1,232-byte transaction; proof is 256, each input 32       | stage inputs in a data account      |
| Default compute budget         | `n = 30`    | 200,000 CU default; `73,612 + 4,174·30 = 198,832`         | `ComputeBudget::set_compute_unit_limit`, up to 1,400,000 |
| Canonical account creation     | `n = 151`   | `MAX_PERMITTED_DATA_INCREASE = 10,240` bytes per CPI growth | none — hard limit, rejected at `InitializeStaging` |

Past roughly 20 public inputs the inputs no longer fit beside the proof in one
transaction and need to be written to a data account ahead of time, with a
`Verify` variant that reads them from that account instead of from instruction
data. (Address lookup tables do not help here — they compress account
*addresses* in the message, not instruction data.) That variant is a design
extension, not part of the current instruction set.

Past 30, callers request a higher compute limit. Past 151, the key cannot be
registered at all; see the README's account-layout section for why the limit is
on the canonical account and cannot be lifted by chunking.

## What is already minimal

Three things bound the floor, and each was checked rather than assumed:

**Four pairs, not three.** Implementations that own the pairing loop fold a
precomputed `e(α, β)` into the final exponentiation and check three pairs
instead of four — worth 12,121 CU. The syscall returns a 32-byte boolean, never
an `Fq12`, so there is nowhere to put a precomputed value.

**No MSM syscall.** `sol_alt_bn128_group_op` exposes G1/G2 add, G1/G2 multiply,
and pairing. There is no multi-scalar-multiplication opcode of the kind
`sol_curve_multiscalar_mul` provides for curve25519, so `4,174n` is the floor
for the public-input combination.

**No on-chain decompression.** Both the key and the proof arrive uncompressed,
so the 13,610 CU G2 decompression never runs. See
[design.md §3](design.md#3-uncompressed-big-endian-everywhere-on-chain).

**No redundant point validation.** The pairing syscall validates every point
with arkworks' `Validate::Yes`, covering the on-curve and subgroup checks
Groth16 soundness needs. See [design.md §6](design.md#6-what-the-syscall-already-checks).

## What is left to optimize

Everything above the floor is SBF-side work: instruction parsing, account
reads, buffer assembly, dispatch. The design pushes that toward zero —
pre-negated G2 in the key, `memcpy`-shaped slot layout, no allocator, no PDA
re-derivation on the hot path — and the benchmark below is what tells us whether
it got there.

One data-dependent saving is available inside the MSM:

| Term               | Saving      |
| ------------------ | ----------- |
| `aᵢ = 0`           | 4,174 (skip both the multiply and the add) |
| `aᵢ = 1`           | 3,840 (skip the multiply, keep the add)    |
| `ICᵢ = O`          | 4,174 (skip both; `aᵢ · O = O` for any `aᵢ`). Only a public input that appears in no constraint has an identity `ICᵢ`, so this is a correctness-preserving no-op for real keys, checked at one 64-byte compare per input |

Zero and one are common in practice — padded input vectors, boolean flags,
selector bits. Skipping costs a comparison against a 32-byte constant, a few
compute units, against 3,840 saved. It makes a verification's CU cost depend on
its public inputs, which is not a leak: public inputs are public by
construction.

With the skip in place the MSM syscall floor is no longer `4,174n` but

```text
3,840 × N_mul + 334 × N_add
```

where `N_mul` counts inputs outside `{0, 1}` and `N_add` counts nonzero inputs.
`4,174n` is the worst case, reached when no input is trivial.

## Publish

Registration is a cold path and is not optimized, but it has to fit in a
transaction, and it has no trivial-scalar shortcut — every `ICᵢ` is validated
regardless of what the public inputs will be. The components, using the same
runtime constants:

| Component                                    | CU                              |
| -------------------------------------------- | ------------------------------- |
| 3-pair validation pairing                    | `36,364 + 2×12,121 + 85 + 576 + 32 = 61,299` |
| `G1_ADD` over adjacent pairs of `IC₁..ICₙ`    | `334 × ⌈n/2⌉` — both operands are validated, an odd tail is added to itself |
| `sha256(body)`                               | `85 + ≤ 1 per byte` — under 10,300 at `n = 151` |
| `find_program_address`                       | `1,500` per attempt; about half of all bumps are off-curve, so expect 2 attempts, and treat 10 (15,000) as a practical worst case |
| Three CPIs (`transfer`, `allocate`, `assign`) | roughly 1,000 each plus serialization |
| Body copy, header write, staging close       | negligible                      |

`G1_ADD` rather than `G1_MUL` for the `ICᵢ` because both deserialize with the
same full validation (`PodG1 → G1` uses `Validate::Yes`), BN254's G1 has
cofactor 1 so on-curve already means in-subgroup, and addition is the cheapest
opcode that runs that deserialization. Only G2 needs the pairing path.

Call it `61,299 + 334·⌈n/2⌉ + ~15,000`. The whole registration chain —
`create_account`, `InitializeStaging`, thirteen 800-byte `Write`s, `Publish` —
for the largest key measures **109,239 CU** under Mollusk (`registry.rs`,
`max_size_key_publishes…`), comfortably inside the default 200,000 budget.

So compute never constrains registration: the `n ≤ 151` size limit binds first
at every `n`. A publishing client should still simulate rather than assume —
`find_program_address` has a small chance of needing many attempts — but the
default budget is expected to suffice for any publishable key.

## Benchmark methodology

Measuring "the pairing" or "the MSM" in isolation means measuring a whole
instruction and subtracting, because Mollusk reports compute units per
instruction. The `bench` crate is a second SBF artifact whose instruction tag
selects how far into the verification to run.

The key, proof and public inputs are **runtime inputs**, carried in the bench
instruction's data as `tag ‖ vk_body ‖ proof ‖ public_inputs` (Mollusk does not
enforce the transaction size limit, so this works for any `n`). They are
deliberately *not* compile-time constants: with the inputs known at build time,
LLVM is entitled to fold the buffer assembly, drop the length and canonicity
checks, and delete any result nothing reads, and the "measurement" would then
be of a different program than the one deployed. Three rules keep the bench
honest:

- every stage calls the same `solana-groth16-verify` functions the real program
  calls, with no bench-only code paths inside the library;
- each stage's result — the assembled buffer, the MSM output, the pairing
  flag — is passed through `core::hint::black_box` and then written to the
  program's return data, so it is observably used;
- the SBF disassembly of `bench` is checked against `program` for the shared
  functions (`llvm-objdump -d` on both `.so` files) whenever the numbers move
  unexpectedly.

The return-data write is measurement scaffolding, and it must not leak into the
numbers. So *every* tag — the baseline included — writes exactly one 64-byte
return-data value, and one extra tag writes nothing at all, so the scaffolding's
own cost can be measured and removed where it matters:

| Tag | Runs                                                        | Return data |
| --- | ----------------------------------------------------------- | ----------- |
| `∅` | Entrypoint, dispatch, parse, construct the key and proof views | none — the views go through `black_box` |
| `0` | Exactly `∅`, then the return-data write                     | 64 bytes of the input, through `black_box` |
| `1` | Parse and assemble the pairing buffer, no syscalls          | 64 bytes of the buffer |
| `2` | The MSM only                                                | `L`, 64 bytes |
| `3` | The pairing only, on the assembled 768-byte buffer          | the 32-byte flag, zero-padded |
| `4` | Full core verification                                      | the 32-byte flag, zero-padded |

Writing `M(t)` for the measurement at tag `t`, and `R = M(0) − M(∅)` for the
cost of the return-data write:

| Quantity                          | Derivation                        | Contains                                   |
| --------------------------------- | --------------------------------- | ------------------------------------------ |
| Scaffolding                       | `R = M(0) − M(∅)`                 | one `sol_set_return_data` of 64 bytes and the copy feeding it — nothing else, because `∅` and `0` share every step before the write |
| Dispatch baseline                 | `M(0)`                            | entrypoint, tag decode, input parse, view construction, `R` |
| Pairing stage                     | `M(3) − M(0)`                     | 73,612 syscall + argument setup, result decode; `R` cancels |
| MSM stage                         | `M(2) − M(0)`                     | `S_msm` syscalls + loop, scalar checks, buffer writes; `R` cancels |
| Core Groth16                      | `M(4) − M(0)`                     | both stages + buffer assembly; `R` cancels |
| **SBF overhead inside core**      | `M(4) − M(0) − 73,612 − S_msm`    | everything in core that is not a syscall   |
| **End-to-end**                    | Mollusk on the real `Verify`      | no return data                             |
| **Account/instruction plumbing**  | `E2E − (M(4) − R)`                | owner and discriminator checks, reading the key from an account rather than instruction data |

Every stage delta subtracts `M(0)`, which carries the same return-data write as
the stage, so `R` cancels there. The end-to-end row is the one place it does
not: the real `Verify` writes no return data, so `M(4)` must have `R` removed
before it is compared. Without that correction the plumbing figure would come
out low by `R`.

## Measurements

`make cu` (Mollusk, SBF arch v2, fresh random arkworks instances). Raw:

```text
inputs      n    M(∅)     M(0)     M(1)     M(2)     M(3)     M(4)      E2E
random      0     102      238      409      378    74029    74166    74005
random      1     102      238      409     4770    74029    78558    78397
random      2     102      238      409     9135    74029    82923    82762
random      4     102      238      409    17865    74029    91653    91492
random      8     102      238      409    35325    74029   109113   108952
random     16     102      238      409    70245    74029   144033   143872
random     32     102      238      409   140085    74029   213873   213712
all zero    8     102      238      409      638    74029    74426    74265
all one     8     102      238      409     4317    74029    78105    77944
```

Derived:

```text
inputs      n      R     S_msm assemble      MSM  pairing      core  overhead  plumbing
random      0    136         0      171      140    73791     73928       316       -25
random      1    136      4174      171     4532    73791     78320       534       -25
random      2    136      8348      171     8897    73791     82685       725       -25
random      4    136     16696      171    17627    73791     91415      1107       -25
random      8    136     33392      171    35087    73791    108875      1871       -25
random     16    136     66784      171    70007    73791    143795      3399       -25
random     32    136    133568      171   139847    73791    213635      6455       -25
all zero    8    136         0      171      400    73791     74188       576       -25
all one     8    136      2672      171     4079    73791     77867      1583       -25
```

What the numbers say:

- **The pairing stage is 73,791**: the 73,612 syscall plus 179 CU of buffer
  assembly and result decode. That 179 is the entire non-syscall cost of the
  pairing path.
- **The MSM stage is `S_msm + ~170 + ~190·n`.** The 190 per input is the
  canonicity compare, the zero/one tests on the scalar, the identity test on
  `ICᵢ`, and copying 96 + 128 bytes into the two syscall input buffers and 64
  bytes back out. With inputs all zero the loop costs 400 for eight inputs —
  the checks, no syscalls. The zero and identity tests OR-reduce eight bytes
  at a time; a byte-wise loop was cheap on random input and cost about 60 CU
  per all-zero input, and the unrolled compare the compiler emits for a fixed
  array was the reverse.
- **The real `Verify` is 25 CU *cheaper* than the bench's core path.** The
  "plumbing" row is `E2E − (M(4) − R)`, and it comes out slightly negative: the
  bench reaches the same core call by parsing `n`, the key body, the proof, the
  inputs and `L` out of instruction data with a bounds check at each split (all
  of which is inside `M(∅) = 102` together with the entrypoint), while the
  program gets there by an owner compare, a discriminator byte, one length
  check and a slice of account data. Those two paths cost about the same, and
  the account path is marginally shorter. Reading the key from an account
  therefore costs nothing relative to reading it from instruction data — the
  question the row was there to answer.
- **Total SBF overhead is `~320 + ~190·n`**, i.e. 0.4% of the total at `n = 0`
  and 3.0% at `n = 32`. The rest is syscalls at fixed prices.

The cost model's two checks hold: `pairing − assemble = 73,620 ≥ 73,612`, and
the MSM stage exceeds `S_msm` by a small positive amount in every row, including
the all-zero and all-one rows where `S_msm` is far below `4,174n`.

`S_msm = 3,840 × N_mul + 334 × N_add` is computed from the benchmark's actual
public inputs, not from `n`, so the overhead row stays meaningful when the
trivial-scalar skip fires. The primary benchmark uses uniformly random field
elements, where `S_msm = 4,174n` with overwhelming probability; a second run
with all-zero and all-one inputs confirms the skip saves what the table above
says it does.

Every stage delta is a lower-bounded measurement: `M(3) − M(0) ≥ 73,612` and
`M(2) − M(0) ≥ S_msm`, with the excess being SBF work around the syscalls that
Mollusk cannot separate out. The syscall figures themselves come from the
runtime constants, not from these measurements. A stage delta *below* its
syscall floor would indicate a cost-model error; a delta above it is expected,
and the size of the gap is what the two bold rows report — they are the only
numbers the program can move.
