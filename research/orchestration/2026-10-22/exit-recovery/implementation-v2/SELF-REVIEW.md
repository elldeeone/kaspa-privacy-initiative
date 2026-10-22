# V2 source preparation checks

No package code was imported or executed. Python AST parsing succeeded for all three new files. Text comparisons confirm byte equality of the original scientific proof/branch/control body, fee function, reused Experiment/Worker code and remaining helper script, owned cleanup functions, and outer timeout/cleanup block. The corresponding block hashes are in prepared-manifest.json. The scientific report changes only the reported Rayon count.

All 65 v1 source pins and three v1 artifact pins matched. Worktree HEAD matched the pinned base, and tracked staged/unstaged diffs were empty. All three existing release executables matched their pinned ordinary-file paths, sizes and hashes. No Rust file, v1 source or v1 manifest was modified; no build, runtime qualification, parameter export, private evaluation read, or proof was performed.

The v2 diff is confined to package/runtime paths; exact original source/build identity gates; a proof-specific parent receipt; N=1..12 CLI, quota and environment checks; fixed CPU affinity 2–13 and corresponding process audits; and output metadata. Cleared sandbox environment still carries only explicit runtime settings. V2 removes the build phase. Runtime configuration never changes fees, note selection, circuit statements, authorization, witnesses or negative-control success criteria.

Pending: independent static review, canonical commit by documentation owner, fresh parent aggregate resource decision, any separately authorized actual v2 envelope qualification, public-only input export and proof release. No runtime acceptance or claim that 12 threads fit 12 GiB is made. Budget termination is incomplete, not semantic failure. No freeze/thaw interface exists.
