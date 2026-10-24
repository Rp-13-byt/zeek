# ZAM compilation caching — investigation findings

**Status:** draft for human review. Not for submission as-is.
**Scope:** evaluate caching ZAM script-optimizer output between runs to speed
up the `-a zam` btest suite (and CI), which currently recompiles everything on
every process start.

**AI assistance:** this investigation, the instrumentation, and the prototype
serializer were produced with AI assistance (Claude). A human contributor must
review the complete diff and this document before any submission, per
`AI_POLICY.md`.

## Reproducing / exercising the work

All additions are gated by environment variables and are completely inert
unless set (normal `-O ZAM` / `-a zam` behavior is unchanged). Build normally,
then:

- `ZEEK_ZAM_TIMING=1` — per-phase wall-clock breakdown of the optimize/compile
  pipeline, printed to stderr at the end of `analyze_scripts()`.
- `ZEEK_ZAM_CACHEABILITY=1` — histogram of which features block serialization;
  `ZEEK_ZAM_CACHE_ASSUME=type:,aux:call-expr,...` marks features as "assumed
  handled" to trace the coverage curve.
- `ZEEK_ZAM_CACHE_KEYS=1` — prints each function's inlining-safe effective key.
- `ZEEK_ZAM_CACHE_VERIFY=1` — round-trip self-verification: serialize +
  deserialize each serializable body and install the reconstructed copy, so the
  btest baselines validate faithfulness. `ZEEK_ZAM_CACHE_DEBUG=1` additionally
  prints serialization coverage. Validated green on `language/` and `core/`.

All of the above require ZAM to be active (`-O ZAM` or `ZEEK_ZAM=1`). The
on-disk cache itself (`ZEEK_ZAM_CACHE_DIR`) is scaffolded (key + fingerprints)
but store/load is not yet wired — see "Remaining".

## Problem

The btest `zam` alternative (`testing/btest/btest.cfg` `[environment-zam]`)
sets `ZEEK_ZAM=1`, which is equivalent to `-O ZAM`. Every one of the ~1900
test processes re-runs the full script-optimization pipeline from scratch over
the base-script corpus it loads. CI runs three `-a zam` jobs
(`.github/workflows/check.yml`: plain, ASan, UBSan), each throttled to
`ZEEK_CI_BTEST_JOBS: 3` "due to OOM issues with ZAM tasks."

There is currently **no** persistence of compiled ZAM output. Vern Paxson's
original 2020 ZAM work included a `ZBody::SaveTo()` "ZAM disk format" (commit
`e6d5432924`), later removed (`b7dff3c067`, "factor out savefile stuff"). The
current code records the intent and the deferral in `ZAM/ZBody.h:45-55`:
"Older code exists for save files, but let's see if we can avoid having to
support them, as they're a fairly elaborate production."

## Measurements

Instrumentation: an env-gated (`ZEEK_ZAM_TIMING`) `ZAMPhaseTimer` was added to
`src/script_opt/ScriptOpt.{h,cc}` and `src/script_opt/ZAM/Driver.cc`, charging
wall-clock time to each pipeline phase and printing a summary at the end of
`analyze_scripts()`. Inert unless the variable is set.

### Per-process overhead is almost entirely the base-script corpus

Wall-clock, default script load, `event zeek_init(){}` (Apple silicon, Debug-ish build):

| scenario                | real   |
|-------------------------|--------|
| ZAM **off**, full base  | 0.68 s |
| ZAM **on**, full base   | 3.51 s |
| ZAM **on**, bare (`-b`) | 0.57 s |

ZAM adds **~2.8 s per process**, essentially 100% attributable to the base
corpus: bare mode adds ~0, and loading several extra protocol/policy scripts on
top of the default load added only 9 functions / ~0.03 s (1345 → 1354). Every
`-a zam` test pays the full ~2.8 s for the same base corpus.

Scale: ~1900 tests × ~2.8 s ≈ **~1.5 h of serial recompute per suite run**,
nearly all redundant, repeated across 3 CI jobs.

### Where the time goes (full base, ~2.56 s in-pipeline, 1345 functions ≈ 1.9 ms/func)

| phase                       | %     |
|-----------------------------|-------|
| reduce                      | 29.2% |
| optimize-AST                | 19.5% |
| usedefs + usedefs-remove    | 27.0% |
| zam-compile                 | 11.1% (of which low-level opt 4.9%) |
| inline                      |  4.4% |
| genid-defs                  |  4.0% |
| reprofile                   |  2.8% |
| profile (ProfileFuncs)      |  1.9% |
| reduce-check                |  ~0%  |

**AST-level optimization (reduce + optimize-AST + usedefs ≈ 76%) dominates; the
final ZAM bytecode emission is only ~11%.**

## Implications for a cache design

1. Caching only the ZAM-emit phase is not worth much (~11%). The expensive work
   is upstream AST optimization. The only large lever is caching the
   **fully-optimized body** — i.e. serialize the final `ZBody` so a cache hit
   skips reduce/optimize-AST/usedefs/compile entirely. That reclaims nearly the
   whole ~2.8 s for unchanged scripts.
2. The change-detection key already exists and is already computed on the ZAM
   path: `ProfileFunc::HashVal()` / `ComputeProfileHash()`
   (`src/script_opt/ProfileFunc.{h,cc}`). The `-O gen-C++` backend already uses
   it as a cross-run cache key (`compiled_scripts[hash]` →
   `func->ReplaceBody()` in `ScriptOpt.cc::use_CPP`).
3. **Inlining caveat (correctness-critical):** `ProfileFuncs` (and every
   `HashVal()`) is computed *before* inlining (`ScriptOpt.cc`: `pfs` built, then
   the `Inliner` runs). ZAM inlines aggressively and coalesces event-handler
   bodies, so a compiled body depends on its inlined callees. A per-body cache
   key must therefore fold in the transitive closure of inlined callees' hashes
   (or key on the post-inline reduced body), not the pre-inline `HashVal()`
   alone. The cache key must also incorporate the Zeek build identity (opcode
   numbering can change) and the active analysis options (`keep-asserts`,
   `no-inline`, `no-ZAM-opt`, …).
4. The hard, missing piece is serialization/deserialization of `ZBody`/`ZInst`.
   A `ZInst` holds live process-interned references: `TypePtr t, t2`, a `ZVal`
   constant, and a `ZInstAux*` (type/constant arrays, iteration info,
   global/lambda/event references). The CPP backend's `InitsInfo`/`RuntimeInits`
   machinery already knows how to reconstruct types, constants, and attributes
   from a compact form and is the natural thing to borrow rather than reviving
   the old text format.

## Security note (per `SECURITY_MODEL.md`)

An on-disk cache that reloads input-derived compiled state is a deserialization
and trust-boundary surface (cache poisoning, stale-across-version loads). A real
implementation needs: a cache keyed/validated by build identity + options,
rejection of malformed/truncated/mismatched files, and adverse-case tests. The
cache should be treated as untrusted on read. (The measurement work above does
not touch this.)

## Cacheability analysis (sizing the serializer)

Before building the full serializer, an env-gated (`ZEEK_ZAM_CACHEABILITY`)
analyzer was added (`ZBody::AssessCacheability`, reported from
`analyze_scripts()`). For a real `-O ZAM` run it inspects every compiled body's
instruction stream and records which features a serializer would have to
handle, with a histogram of blockers. A second knob
(`ZEEK_ZAM_CACHE_ASSUME=<labels/prefixes>`) marks features as "assumed handled"
so coverage can be measured as serializer capability grows.

Scope note: the analyzer assesses the instruction stream (ops, operands,
per-instruction types, constants, and `ZInstAux` contents). Body-level
structures (switch case-maps, globals, frame layout) are not yet assessed;
those are bounded and largely by-name/atomic, but must be covered by the real
serializer.

### Blocker histogram (full base corpus, 1345 bodies, 56 973 instructions)

Top blockers by fraction of bodies they block:

| blocker            | bodies blocked | notes |
|--------------------|----------------|-------|
| aux:call-expr      | 79.1% | `CallExpr` on call insts — backtrace + trigger-lookup key |
| aux:id-val         | 77.8% | `IDPtr` for function-name access — by-name |
| type:record        | 76.2% | record types — needs type reconstruction |
| aux:direct-func    | 57.9% | `Func*` for direct calls — by-name |
| type:table         | 54.5% | table types |
| type/const:enum    | 42.5% / 34.5% | enum types/consts — by-name |
| type:func          | 26.6% | function types |
| type:vector/any    | 18.6% / 13.5% | |
| aux:event-handler  | 10.8% | `EventHandler*` — by-name |
| aux:field-inits    | 9.3% | record constructors |
| aux:cat-args/attrs | 5.9% / 0.1% | |
| aux:lambda         | 1.9% | lambda construction (AST) |
| aux:when-info      | 0.7% | `when` statements (AST) |

### Coverage curve (cumulative serializer capability)

| tier | capability added | bodies cacheable | instructions clean |
|------|------------------|------------------|--------------------|
| A | atomic scalars only (baseline) | 1.9% | 40.0% |
| B | + type/const reconstruction (all types) | 11.4% | 83.5% |
| C | + by-name refs (id-val, direct-func, event-handler) | 19.0% | 89.7% |
| D | + call-expr | **84.2%** | 99.3% |
| E | + record constructors (field-inits, attrs, cat-args) | **98.1%** | 99.9% |
| F | everything except lambda + when-info | 98.1% | 99.9% |
| G | everything | 100% | 100% |

### Readout

- **Type reconstruction is the mandatory foundation** (A→B: instructions
  40%→83.5%). This is exactly what the CPP backend's `InitsInfo`/`RuntimeInits`
  already does and should be borrowed rather than reinvented.
- **`aux:call-expr` is the single highest-leverage item** (C→D: bodies
  19%→84%). It is not cosmetic: `OPs/calls.op` uses it both as the frame's
  current-call for backtraces (`SetCall`) and as a trigger-lookup key
  (`trigger->Lookup`). But it is bounded, reconstructible AST + a location, not
  a fundamental blocker. The pointer-identity-as-trigger-key use (only in
  `when`/trigger contexts, which are themselves rare) is the subtlety to handle.
- **Record constructors** (field-inits/attrs/cat-args) take coverage to 98.1%.
- **`lambda` + `when-info` are the entire remaining 1.9%** and are the
  genuinely hard AST cases. A serializer can simply fall back to normal
  compilation for those bodies and still cache ~98% — so they need not be in
  the first implementation.

### Serializer roadmap (priority order)

1. Type + constant (de)serialization — reuse CPP `InitsInfo` machinery. *(req.)*
2. By-name rebinding of `id_val`, `func`, `event_handler` against the running
   global/event registries.
3. A compact `call_expr` representation (location + call identity; full fidelity
   only where trigger/`when` semantics require it).
4. Record-constructor aux (`field_inits`, `attrs`, `cat_args`) and the aux
   type/map vectors.
5. Body-level structures: frame layout/denizens, globals, switch case-maps.
6. Fall back to normal compilation for bodies containing lambdas or `when`
   (≈1.9%); add later if worthwhile.

Expected coverage after steps 1–4: ~98% of bodies, which at ~2.8 s/process over
the base corpus is essentially the whole win.

## Effective cache key (validated)

A per-body cache must share the base corpus across tests (each test's *total*
program differs, so a whole-program key would never hit). The key must also be
inlining-safe: `ComputeProfileHash()` folds in identifier names/types/constants
but not called-function bodies, so a bare `HashVal()` is unsafe when inlining is
on.

`effective_cache_key(pf, pfs)` (in `ScriptOpt.cc`) = `pf->HashVal()` merged with
the `HashVal()` of every script function transitively reachable through the call
graph, combined over a sorted set (order-independent, cycle-safe). Inlined
callees ⊆ called functions, so this is a safe over-approximation (a changed
non-inlined callee only causes a conservative miss, never a wrong hit). The
file-level key additionally folds in build identity + analysis options.

Validated via the `ZEEK_ZAM_CACHE_KEYS` diagnostic:
- Deterministic across runs: 918 non-lambda base functions produced identical
  keys run-to-run (0 diffs); lambda key-hashes were an identical multiset (only
  lambda *display names* are nondeterministic, and lambdas fall back to normal
  compilation).
- Stable under test-specific additions: adding a function that calls into the
  base corpus changed **0** base-function keys — so base bodies hit the cache
  regardless of which test loads them.

## Serialization architecture (decided, from substrate survey)

Zeek has no general `Type` serializer, but two facts make the ZAM cache
tractable without reconstructing types from scratch:

- The cache is loaded **after** the (identical) scripts are parsed, so every
  `Type`/named `ID`/`Func`/`EventHandler` an instruction references **already
  exists** in the loading process.
- `ProfileFuncs` already computes a stable, content-derived hash for every type
  (`HashType`) and keeps a hash → representative-`Type*` map (`type_hash_reps`,
  now exposed as `TypeForHash`).

Resulting codec decisions:

- **Types:** serialize as the profile **type-hash**; at load resolve via
  `ProfileFuncs::TypeForHash(h)` against the current process. Uniform for named
  and anonymous/compound types; no structural rebuild. A type not present in
  the map at store time makes that body non-cacheable (gated out).
- **Atomic constants:** serialize by value and rebuild via `val_mgr` /
  `make_intrusive<…>` (addr/subnet via string ctor, port via packed uint, enum
  via its type-hash + int). Container constants gated out initially (rare as
  instruction constants).
- **By-name references** (`aux.id_val`, `aux.func`, `aux.event_handler`):
  serialize the name; resolve via `lookup_ID` / `zeek::id::find_func` /
  `event_registry` at load.
- **Validation / key:** follow house style (hash-stamping, not a magic number).
  The file-level key folds each body's `effective_cache_key` plus build identity
  (`zeek_version()` + a format-version constant + the executable's mtime) and an
  analysis-options hash. Any mismatch ⇒ whole-file miss ⇒ normal compilation.
- **Capability gate (correctness invariant):** a body is cached only if every
  instruction is fully serializable under the implemented capability; otherwise
  it is compiled normally. The cache can therefore never cause an incorrect
  execution — at worst a miss. `lambda`/`when` bodies always fall back.

Reused from CPP where applicable: the name→Type/ID resolvers
(`get_record_type__CPP`-style via `global_scope()->Find`), and the
reconstruction *logic* patterns in `RuntimeInits.cc` (not the C++-emission half).

## Implementation status (prototype in progress)

All additions are behind env gates and inert otherwise; the build is clean and
normal ZAM behavior is unchanged when the gates are off.

Landed:
- `ZAMBodyCache` module (`src/script_opt/ZAM/BodyCache.{h,cc}`): opt-in via
  `ZEEK_ZAM_CACHE_DIR`, with the validated `EffectiveKey`, build-id, and
  options-hash fingerprints.
- `ZBodySerializer`: serialize/deserialize of a compiled `ZBody`. Implemented:
  instruction stream (ops, operands), per-instruction types (by profile
  type-hash, resolved to live `TypePtr` via `ProfileFuncs::TypeForHash`), atomic
  constants (bool/int/count/double/time/interval/string/addr/subnet/port/enum),
  frame denizens/size, managed slots, modules, fixed-frame. A capability gate
  declines any body with globals, switches, loops, aux, or non-atomic
  constants, so unsupported bodies fall back to normal compilation.
- Round-trip self-verification mode (`ZEEK_ZAM_CACHE_VERIFY`): compiles, then
  serializes + deserializes each serializable body and installs the
  reconstructed copy, so the existing btest baselines validate faithfulness.

Also landed:
- **Globals** serialized by name (re-resolved via `lookup_ID`).
- **`ZInstAux` serialization (step 1)**: elems (slots/ints/atomic constants with
  type hashes), the int-vector maps, type/is_managed vectors, loop vars,
  value_var_type, the flags, the control-flow map, the `zvec` scratch size, and
  the `id_val`/`func`/`event_handler` references (by name). Still gated:
  `lambda`, `wi`, `cat_args`, `attrs`, `field_inits`, `call_expr`, and
  record/vector-construction maps. This raised round-trip coverage of the base
  corpus from ~1.6% to ~14.7% of bodies.
- **On-disk store/load** (`ZAMBodyCache::Store`/`TryLoad`): each serializable
  body is persisted to `ZEEK_ZAM_CACHE_DIR/zam-<key>.zbc` with a header (magic,
  format version, build id, options hash, key); writes use temp-file + atomic
  rename for safe concurrent access. `analyze_scripts_for_ZAM` loads before
  compiling and installs on a hit (skipping `optimize_func`), storing on a miss.
  The deserialization ctor runs the one-time ZAM runtime init so a pure
  cache-hit run (which compiles nothing) is sound. The cache is disabled in
  diagnostic modes (usage analysis, dumps, profiling).

Validated:
- `language/` and `core/` suites under `-a zam` with round-trip verify: **453/453
  and 284/284 pass**, identical to control.
- `language/` and `core/` run **cold (populating) then warm (pure cache-hit)**
  over a shared cache dir: both passes **453/453** and **284/284** — the
  load-and-install path that skips `optimize_func` is correct.

Performance note: at the current ~14.7% body coverage the measured speedup is
negligible — the cacheable bodies are the cheap ones, while the expensive
call/record-bearing bodies are still gated and recompiled, and the `profile`
and `inline` phases run regardless. The win materializes as coverage grows
(see below); the ceiling is roughly the ~87% of per-process ZAM cost that is
reduce/optimize-AST/use-defs/compile.

Remaining (coverage growth + productization):
- **`call_expr` — the biggest remaining lever** (~19%→~84% of bodies). Used at
  run time only as the frame's current-call for backtraces (`SetCall`) and as a
  trigger/`when` memoization key (`trigger->Lookup`), so a reconstructed stand-in
  carrying the call's location and a stable identity may suffice without full
  AST serialization — to be confirmed.
- **Record/vector constructors** (`field_inits`, `attrs`, `cat_args`, the
  construction maps) — to ~98%. Note the `zvec`/`vv` runtime-scratch hazard:
  `zvec` is pre-sized by the compiler (its size is already serialized), and
  field-init default values may be pre-populated at compile time (so their
  contents, not just the size, would need serializing).
- Body-level structures still gated: switch case-maps, table/step iterators.
- A stronger `BuildId` (executable fingerprint, not just version string) and the
  security hardening noted below before any default-on use. Skipping `profile`
  and `inline` on a full-cache-hit run is also a future optimization.

## Recommendation

Proceed to the on-disk `ZBody` cache (serialize fully-optimized bodies, key on
an inlining-aware hash + build-id + options), implementing the roadmap above in
priority order and validating against existing btest baselines at each step.
Steps 1–4 reach ~98% coverage; lambdas/`when` fall back to normal compilation.
Treat the on-disk cache as an untrusted deserialization boundary per
`SECURITY_MODEL.md` (build-id/options validation, malformed-input rejection,
adverse-case tests).
