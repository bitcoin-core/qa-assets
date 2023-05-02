# qa-assets

Bitcoin Core related blobs used for quality assurance.

## Fuzz inputs

`qa-assets/fuzz_seed_corpus` contains one input corpus per fuzz target (one
folder per target named the same as each target).

### Contributing inputs

*For documentation on how to fuzz Bitcoin Core please see
[fuzzing.md](https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md).*

If you want to contribute fuzz inputs, please "merge" the inputs before
submitting a pull request. You can use the libFuzzer option `-merge=1`
(recommended with `-use_value_profile=1`) or the `--m_dir` option of the fuzz
runner:
[`test_runner.py`](https://github.com/bitcoin/bitcoin/blob/master/test/fuzz/test_runner.py).

### Pruning inputs 

* Over time fuzz engines reduce inputs (produce a smaller input that yields the
  same coverage statistics), which causes our copora to accumulate larger
  non-reduced inputs. 
* Code changes can lead to inputs losing their coverage.

To avoid corpora bloat, stale inputs and potential CI timeouts, we usually
prune/minimize our copora around the branch-off point using the
[`delete_nonreduced_fuzz_inputs.sh`](https://raw.githubusercontent.com/bitcoin-core/bitcoin-maintainer-tools/main/delete_nonreduced_fuzz_inputs.sh)
script (Recommended to run in a fresh VM, see documentation in the script). The
script is usually run twice to ensure that the results are "somewhat"
reproducible (e.g.
https://github.com/bitcoin-core/qa-assets/pull/119#issuecomment-1518019457).

After pruning the corpora, the coverage should not have dropped at all.

### Pulling inputs from oss-fuzz

Use `download_oss_fuzz_inputs.py` to pull fuzz inputs from oss-fuzz.
