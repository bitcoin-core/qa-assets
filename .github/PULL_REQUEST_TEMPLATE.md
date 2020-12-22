If you are adding fuzz seeds, please "merge" the seeds before submitting this
pull request, then remove the instruction text here.

You can use the libFuzzer option `-merge=1` (recommended with
`-use_value_profile=1`) or the `--m_dir` option of the fuzz runner:
https://github.com/bitcoin/bitcoin/blob/master/test/fuzz/test_runner.py
