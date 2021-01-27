# Over time the fuzz engine will reduce inputs (produce a smaller input that
# yields the same coverage statistics). With a growing set of inputs, it could
# be useful to occasionally delete the "old" non-reduced inputs.
#
# This script tries to do so in a way that is as deterministic as possible.
#
# The script should be run on an x86_64 virtual machine with only a minimal
# vanilla Ubuntu Focal 20.04 installed.  Ideally, the script was run on
# different architectures or even different OS versions, which come with
# different library packages, but this is left as a future improvement.

export BITCOIN_CORE_COMMIT="80486e7e2d8c360839cffc5a0c597b5c745433a7"
export FUZZ_INPUTS_DIR="fuzz_seed_corpus"

set -e

echo "Installing Bitcoin Core build deps"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y \
  git \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 \
  libevent-dev libboost-test-dev libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
  clang llvm

git clone https://github.com/bitcoin-core/qa-assets.git
(
  cd qa-assets
  mv ./"${FUZZ_INPUTS_DIR}" all_inputs
  git config user.name "delete_nonreduced_inputs script"
  git config user.email "noreply@noreply.noreply"
  git commit -a -m "Delete fuzz inputs"
)

git clone https://github.com/bitcoin/bitcoin.git
(
  cd bitcoin
  git checkout "${BITCOIN_CORE_COMMIT}"

  ./autogen.sh

  for sanitizers in {"fuzzer,address,undefined,integer","fuzzer"}; do
    echo "Adding reduced seeds for sanitizer=${sanitizer}"

    ./configure CC=clang CXX=clang++ --enable-fuzz --with-sanitizers="${sanitizer}"
    make clean
    make -j $(nproc)

    ./test/fuzz/test_runner.py -l DEBUG --par=$(nproc) --m_dir=../all_inputs ../qa-assets/"${FUZZ_INPUTS_DIR}"

    (
      cd ../qa-assets
      git add "${FUZZ_INPUTS_DIR}"
      git commit -m "Reduced inputs for ${sanitizer}"
    )
  done
)
