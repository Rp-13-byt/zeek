// See the file "COPYING" in the main distribution directory for copyright.

// On-disk cache of compiled ZAM function bodies.
//
// ZAM compilation recomputes the full optimize+compile pipeline on every
// process start. For workloads that repeatedly compile the same scripts (most
// notably the `-a zam` btest suite, where ~1900 processes each recompile the
// identical base-script corpus), this is almost entirely redundant work. This
// cache serializes fully-compiled bodies to disk, keyed by an inlining-safe
// per-body key plus the build identity and analysis options, and installs them
// on a subsequent run instead of recompiling.
//
// Correctness invariant: the cache can only ever skip recompilation of a body
// whose serialized form matches the current build, the active analysis options,
// and the body's (inlining-safe) effective key. On any mismatch, corruption, or
// not-yet-supported feature it falls back to normal compilation. It can
// therefore never cause an incorrect execution -- at worst a cache miss.
//
// The cache is opt-in: it is active only when the environment variable
// ZEEK_ZAM_CACHE_DIR names a directory. Otherwise every method is inert and ZAM
// behaves exactly as before.

#pragma once

#include <string>

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

// Bump whenever the on-disk format or any ZAM encoding detail changes, so old
// cache files are rejected rather than misread.
constexpr uint32_t ZAM_CACHE_FORMAT_VERSION = 1;

class ZAMBodyCache {
public:
    // Reads ZEEK_ZAM_CACHE_DIR; if set and usable, computes the build-identity
    // and analysis-options fingerprints that scope every cache entry.
    ZAMBodyCache();

    bool Enabled() const { return enabled; }
    const std::string& Dir() const { return dir; }

    // The inlining-safe effective key for a function: its own profile HashVal()
    // merged with the HashVal() of every script function transitively reachable
    // through its call graph. Inlined callees are a subset of called functions,
    // so this is a safe over-approximation -- the key changes whenever the body
    // or any transitively called body changes. Combination is over a sorted set
    // (order-independent, cycle-safe). This is build/options independent; the
    // cache separately scopes entries by BuildId()/OptionsHash().
    static p_hash_type EffectiveKey(const ProfileFunc* pf, const ProfileFuncs& pfs);

    // Fingerprints that must match for a cache entry to be reused. BuildId
    // captures anything that can change ZAM output across binaries; OptionsHash
    // captures the ZAM-affecting analysis options.
    const std::string& BuildId() const { return build_id; }
    p_hash_type OptionsHash() const { return options_hash; }

private:
    void ComputeBuildId();
    void ComputeOptionsHash();

    bool enabled = false;
    std::string dir;
    std::string build_id;
    p_hash_type options_hash = 0;
};

} // namespace zeek::detail
