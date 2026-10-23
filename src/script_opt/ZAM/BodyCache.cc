// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/BodyCache.h"

#include <cstdlib>
#include <set>
#include <unordered_set>
#include <vector>

#include "zeek/script_opt/ScriptOpt.h"

namespace zeek {
extern const char* zeek_version();
}

namespace zeek::detail {

ZAMBodyCache::ZAMBodyCache() {
    const char* d = getenv("ZEEK_ZAM_CACHE_DIR");
    if ( ! d || ! *d )
        return;

    dir = d;
    enabled = true;

    ComputeBuildId();
    ComputeOptionsHash();
}

p_hash_type ZAMBodyCache::EffectiveKey(const ProfileFunc* pf, const ProfileFuncs& pfs) {
    std::set<p_hash_type> hashes; // sorted + deduplicated -> order-independent
    hashes.insert(pf->HashVal());

    std::unordered_set<const ScriptFunc*> seen;
    std::vector<const ProfileFunc*> work{pf};

    while ( ! work.empty() ) {
        auto cur = work.back();
        work.pop_back();

        for ( auto sf : cur->ScriptCalls() ) {
            if ( ! seen.insert(sf).second )
                continue;
            auto it = pfs.FuncProfs().find(sf);
            if ( it == pfs.FuncProfs().end() )
                continue; // e.g. a BiF or otherwise unprofiled; covered by BuildId
            hashes.insert(it->second->HashVal());
            work.push_back(it->second.get());
        }
    }

    p_hash_type h = 0;
    for ( auto x : hashes )
        h = merge_p_hashes(h, x);
    return h;
}

void ZAMBodyCache::ComputeBuildId() {
    // The build identity must change whenever the compiled ZAM output could
    // change across zeek binaries (opcode numbering, codegen, runtime support).
    //
    // TODO(prototype): this uses the version string plus the format version,
    // which does NOT change between local rebuilds of the same version. Before
    // this cache is enabled by default it must incorporate a true binary
    // fingerprint (e.g. the executable's mtime/size or a content hash) so a
    // rebuilt zeek never loads bytecode produced by a previous build.
    build_id = std::string(zeek::zeek_version()) + ";zam-cache-v" + std::to_string(ZAM_CACHE_FORMAT_VERSION);
}

void ZAMBodyCache::ComputeOptionsHash() {
    // Fold in every analysis option that changes the compiled ZAM output.
    const auto& o = analysis_options;
    p_hash_type h = p_hash(static_cast<int>(ZAM_CACHE_FORMAT_VERSION));

    auto add_bool = [&](bool b) { h = merge_p_hashes(h, p_hash(b ? 1 : 0)); };
    add_bool(o.compile_all);
    add_bool(o.optimize_AST);
    add_bool(o.inliner);
    add_bool(o.no_inliner);
    add_bool(o.no_eh_coalescence);
    add_bool(o.keep_asserts);
    add_bool(o.no_ZAM_opt);
    add_bool(o.no_ZAM_control_flow_opt);

    options_hash = h;
}

} // namespace zeek::detail
