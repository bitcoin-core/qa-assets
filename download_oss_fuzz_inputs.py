#!/usr/bin/env python3

import argparse
import os
import subprocess


FUZZ_INPUTS_DIR = "fuzz_seed_corpus"
ZIP_NAME = "public.zip"
BOLD = ("\033[0m", "\033[1m")


def main():
    THIS_FILE_PATH = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
    parser = argparse.ArgumentParser(
        description="Download public archives of OSS-Fuzz inputs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--download_dir",
        help="The local dir to download to",
        default=os.path.join(THIS_FILE_PATH, "oss_fuzz_inputs"),
    )
    args = parser.parse_args()

    download_dir = os.path.join(args.download_dir, "")
    os.makedirs(download_dir, exist_ok=False)

    existing_dir = os.path.join(THIS_FILE_PATH, FUZZ_INPUTS_DIR)
    existing_targets = sorted([i.name for i in os.scandir(existing_dir) if i.is_dir()])

    os.chdir(download_dir)
    for target in existing_targets:
        print(f'{BOLD[1]}Downloading for target "{target}" ...{BOLD[0]}')
        url = f"https://storage.googleapis.com/bitcoin-core-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/bitcoin-core_{target}/{ZIP_NAME}"
        if 0 != subprocess.call(["wget", url]):
            print(f'{BOLD[1]}... Skipping target "{target}"{BOLD[0]}')
            continue
        subprocess.check_call(["unzip", "-n", "-q", ZIP_NAME, "-d", target])
        os.remove(ZIP_NAME)
        print(f'{BOLD[1]}... Done target "{target}"{BOLD[0]}')


if __name__ == "__main__":
    main()
