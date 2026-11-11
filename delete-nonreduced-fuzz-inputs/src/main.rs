// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Over time the fuzz engine will reduce inputs (produce a smaller input that
// yields the same coverage statistics). With a growing set of inputs, it could
// be useful to occasionally delete the "old" non-reduced inputs.
//
// This script tries to do so in a way that is as deterministic as possible.
//
// The script should be run on an x86_64 virtual machine with only a minimal
// vanilla Ubuntu Resolute 26.04 installed. Ideally, the script was run on
// different architectures or even different OS versions, which come with
// different library packages, but this is left as a future improvement. Also,
// it's recommended to run the script twice to ensure that the results are
// "somewhat" reproducible.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// A type for a complete and readable error message.
type AppError = String;
type AppResult = Result<(), AppError>;

/// A fuzz engine whose corpus minimizer can't merge into an existing corpus.
struct Minimizer {
    name: &'static str,
    build: fn(&str) -> AppResult,
    /// Args: fuzz target, input dir, new output dir.
    minimize: fn(&str, &Path, &Path) -> AppResult,
    /// Number of fuzz targets minimized at once.
    jobs: usize,
}

/// Apt packages that will be installed.
const APT_PACKAGES: &[&str] = &[
    "git",
    "build-essential",
    "pkg-config",
    "bsdmainutils",
    "python3",
    "cmake",
    "libcapnp-dev",
    "capnproto",
    "libsqlite3-dev",
    "libevent-dev",
    "libboost-dev",
    "binutils-dev",
    "liblzma-dev",
    "libunwind-dev",
];
/// Path to the cloned qa-assets repository.
const QA_ASSETS_PATH: &str = "qa-assets";
/// The name of the directory in qa-assets that holds the committed fuzz corpora.
const FUZZ_CORPORA_DIR: &str = "fuzz_corpora";
/// Path to the cloned bitcoin repository.
const BITCOIN_PATH: &str = "bitcoin";
/// Bitcoin build directory.
const BITCOIN_BUILD_DIR: &str = "build_fuzz";
/// Scratch dir for a minimized corpus, before it is added to the committed corpora.
const MINIMIZED_DIR: &str = "minimized";
/// Where honggfuzz writes the files it keeps, which can be prefixes of inputs.
const HONGGFUZZ_OUTPUT_DIR: &str = "honggfuzz_output";
/// Per-input timeout of afl-cmin and honggfuzz. It is libFuzzer's default, which the libFuzzer
/// merge uses, as a timed out input is only judged on its partial coverage.
const MINIMIZER_TIMEOUT_SECS: u64 = 1200;

/// honggfuzz has no stable branch and its last release is from 2023, so pin a master commit.
const HONGGFUZZ_COMMIT: &str = "940b958dfeb6f9131fd846cae31fcc0fe996ae98";

const LLVM_VERSION: &str = "20";
const SANITIZERS: &[&str] = &["fuzzer", "fuzzer,address,undefined,integer"];

fn help(err: &str) -> AppError {
    format!(
        r#"
Error: {err}

Usage: delete-nonreduced-fuzz-inputs [--extra-ref=<ref>]...

Note: <ref> must be a tag or branch
"#
    )
}

fn parse_cli_args() -> Result<Vec<String>, AppError> {
    let mut git_refs = Vec::new();
    for arg in env::args().skip(1) {
        if arg == "-h" || arg == "--help" {
            Err(help("Help requested"))?;
        } else if let Some(value) = arg.strip_prefix("--extra-ref=") {
            if value.is_empty() {
                return Err(help("empty value for --extra-ref"));
            }
            git_ls_remote("https://github.com/bitcoin/bitcoin", value)?;
            git_refs.push(value.to_string());
        } else {
            Err(help(&format!("Too many args, or unknown named arg: {arg}")))?;
        }
    }
    Ok(git_refs)
}

fn app() -> AppResult {
    let mut git_refs = vec!["master".to_string()];
    let extra_refs = parse_cli_args()?;
    git_refs.extend(extra_refs);

    install_deps()?;
    clone_and_configure_repositories()?;

    let all_inputs_dir = move_fuzz_inputs()?;
    // git commit -a does not add untracked removed files
    git_add(QA_ASSETS_PATH, FUZZ_CORPORA_DIR)?;
    git_commit(QA_ASSETS_PATH, "Delete fuzz inputs")?;

    let fuzz_corpora_dir_path = Path::new(QA_ASSETS_PATH).join(FUZZ_CORPORA_DIR);

    // Engines measure coverage differently, so each one minimizes the full all_inputs.
    let minimizers = [
        Minimizer {
            name: "afl-cmin",
            build: build_bitcoin_afl,
            minimize: run_afl_cmin,
            // afl-cmin already uses all cores
            jobs: 1,
        },
        Minimizer {
            name: "honggfuzz",
            build: build_bitcoin_honggfuzz,
            minimize: run_honggfuzz_minimize,
            // honggfuzz minimizes on a single thread
            jobs: nproc(),
        },
    ];
    for minimizer in &minimizers {
        for git_ref in &git_refs {
            println!("Adding reduced seeds with {} on {git_ref}", minimizer.name);
            (minimizer.build)(git_ref)?;
            add_minimized_inputs(&all_inputs_dir, &fuzz_corpora_dir_path, minimizer)?;
            git_add(QA_ASSETS_PATH, FUZZ_CORPORA_DIR)?;
            git_commit(
                QA_ASSETS_PATH,
                &format!("Reduced inputs for {} on {git_ref}", minimizer.name),
            )?;
        }
    }

    for git_ref in &git_refs {
        for sanitizer in SANITIZERS {
            println!("Adding reduced seeds for {sanitizer} on {git_ref}");
            build_bitcoin_with_sanitizer(git_ref, sanitizer)?;
            run_libfuzzer(&all_inputs_dir, &fuzz_corpora_dir_path)?;
            git_add(QA_ASSETS_PATH, FUZZ_CORPORA_DIR)?;
            git_commit(
                QA_ASSETS_PATH,
                &format!("Reduced inputs for {sanitizer} on {git_ref}"),
            )?;
        }
    }

    println!("✨ Saved minimized fuzz corpora. ✨");
    Ok(())
}

fn install_deps() -> AppResult {
    install_apt_deps()?;
    install_llvm()?;
    install_aflpp()?;
    install_honggfuzz()?;
    Ok(())
}

fn install_apt_deps() -> AppResult {
    env::set_var("DEBIAN_FRONTEND", "noninteractive");

    if !Command::new("apt")
        .arg("update")
        .status()
        .map_err(|e| format!("failed to spawn apt: {e}"))?
        .success()
    {
        Err("apt update failed".to_string())?;
    }

    if !Command::new("apt")
        .args(["install", "-y"])
        .args(APT_PACKAGES)
        .status()
        .map_err(|e| format!("failed to spawn apt: {e}"))?
        .success()
    {
        Err("apt install failed".to_string())?;
    }

    Ok(())
}

fn install_llvm() -> AppResult {
    let packages = [
        format!("clang-{LLVM_VERSION}"),
        format!("llvm-{LLVM_VERSION}"),
        format!("libc++abi-{LLVM_VERSION}-dev"),
        format!("libc++-{LLVM_VERSION}-dev"),
        format!("libclang-{LLVM_VERSION}-dev"),
        format!("libclang-cpp{LLVM_VERSION}-dev"),
        format!("libclang-common-{LLVM_VERSION}-dev"),
        format!("libclang-rt-{LLVM_VERSION}-dev"),
        format!("llvm-{LLVM_VERSION}-dev"),
        format!("lld-{LLVM_VERSION}"),
    ];

    if !Command::new("apt")
        .args(["install", "-y"])
        .args(&packages)
        .status()
        .map_err(|e| format!("failed to spawn apt: {e}"))?
        .success()
    {
        Err("apt install LLVM packages failed".to_string())?;
    }

    if !Command::new("sh")
        .args([
            "-c",
            &format!("ln -sv $(which llvm-symbolizer-{LLVM_VERSION}) /usr/bin/llvm-symbolizer"),
        ])
        .status()
        .map_err(|e| format!("failed to spawn sh: {e}"))?
        .success()
    {
        Err("linking llvm-symbolizer failed".to_string())?;
    }

    Ok(())
}

fn install_aflpp() -> AppResult {
    let clone_path = "AFLplusplus";
    git_clone(
        "https://github.com/AFLplusplus/AFLplusplus",
        &["--branch=stable", "--depth=1"],
        clone_path,
    )?;
    if !Command::new("make")
        .args([
            "-C",
            clone_path,
            &format!("LLVM_CONFIG=llvm-config-{LLVM_VERSION}"),
            "PERFORMANCE=1",
            "install",
            &format!("-j{}", nproc()),
        ])
        .status()
        .map_err(|e| format!("failed to spawn make: {e}"))?
        .success()
    {
        Err("make install AFLplusplus failed".to_string())?;
    }

    Ok(())
}

fn install_honggfuzz() -> AppResult {
    let clone_path = "honggfuzz";
    git_clone(
        "https://github.com/google/honggfuzz",
        &[&format!("--revision={HONGGFUZZ_COMMIT}"), "--depth=1"],
        clone_path,
    )?;
    if !Command::new("make")
        .args(["-C", clone_path, "install", &format!("-j{}", nproc())])
        .status()
        .map_err(|e| format!("failed to spawn make: {e}"))?
        .success()
    {
        Err("make install honggfuzz failed".to_string())?;
    }

    Ok(())
}

fn clone_and_configure_repositories() -> AppResult {
    git_clone(
        "https://github.com/bitcoin-core/qa-assets.git",
        &["--depth=1"],
        QA_ASSETS_PATH,
    )?;
    git_config(
        QA_ASSETS_PATH,
        "user.name",
        "delete_nonreduced_inputs script",
    )?;
    git_config(QA_ASSETS_PATH, "user.email", "noreply@noreply.noreply")?;
    git_clone(
        "https://github.com/bitcoin/bitcoin.git",
        &["--depth=1"],
        BITCOIN_PATH,
    )?;

    Ok(())
}

fn move_fuzz_inputs() -> Result<PathBuf, AppError> {
    let src = Path::new(QA_ASSETS_PATH).join(FUZZ_CORPORA_DIR);
    if !src.is_dir() {
        return Err("fuzz corpora not found".to_string());
    }

    let dst = Path::new("all_inputs");
    if dst.exists() {
        return Err("all_inputs already exists".to_string());
    }
    fs::rename(src, dst).map_err(|e| format!("failed to move fuzz corpora: {e}"))?;

    Ok(dst.to_path_buf())
}

fn git_clone<P: AsRef<Path>>(url: &str, clone_args: &[&str], clone_path: P) -> AppResult {
    if !Command::new("git")
        .arg("clone")
        .args(clone_args)
        .arg(url)
        .arg(clone_path.as_ref())
        .status()
        .map_err(|e| format!("failed to spawn git clone: {e}"))?
        .success()
    {
        return Err(format!("git clone {url} failed"));
    }

    Ok(())
}

fn git_config<P: AsRef<Path>>(repo_path: P, key: &str, value: &str) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .args(["config", key, value])
        .status()
        .map_err(|e| format!("failed to spawn git config: {e}"))?
        .success()
    {
        return Err("git config failed".to_string());
    }

    Ok(())
}

fn git_add<P: AsRef<Path>, Q: AsRef<Path>>(repo_path: P, file_path: Q) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .arg("add")
        .arg(file_path.as_ref())
        .status()
        .map_err(|e| format!("failed to spawn git add: {e}"))?
        .success()
    {
        return Err("git add failed".to_string());
    }

    Ok(())
}

fn git_commit<P: AsRef<Path>>(repo_path: P, message: &str) -> AppResult {
    if !Command::new("git")
        .current_dir(repo_path)
        .args(["commit", "--allow-empty", "-m", message])
        .status()
        .map_err(|e| format!("failed to spawn git commit: {e}"))?
        .success()
    {
        return Err("git commit failed".to_string());
    }

    Ok(())
}

fn git_ls_remote(remote: &str, git_ref: &str) -> AppResult {
    if !Command::new("git")
        .args(["ls-remote", "--exit-code", remote, git_ref])
        .status()
        .map_err(|e| format!("failed to spawn git ls-remote: {e}"))?
        .success()
    {
        return Err(format!("git ls-remote: {git_ref} not found"));
    }

    Ok(())
}

fn build_bitcoin_afl(git_ref: &str) -> AppResult {
    build_bitcoin(
        git_ref,
        &[
            "-DCMAKE_C_COMPILER=afl-clang-fast",
            "-DCMAKE_CXX_COMPILER=afl-clang-fast++",
            "-DBUILD_FOR_FUZZING=ON",
        ],
    )
}

fn build_bitcoin_honggfuzz(git_ref: &str) -> AppResult {
    // hfuzz-clang otherwise wraps whichever clang it finds first.
    env::set_var("HFUZZ_CC_PATH", format!("clang-{LLVM_VERSION}"));
    env::set_var("HFUZZ_CXX_PATH", format!("clang++-{LLVM_VERSION}"));
    // Same sanitizers as Bitcoin Core's doc/fuzzing.md, since they change the coverage edges.
    build_bitcoin(
        git_ref,
        &[
            "-DCMAKE_C_COMPILER=hfuzz-clang",
            "-DCMAKE_CXX_COMPILER=hfuzz-clang++",
            "-DBUILD_FOR_FUZZING=ON",
            "-DSANITIZERS=address,undefined",
        ],
    )
}

fn build_bitcoin_with_sanitizer(git_ref: &str, sanitizer: &str) -> AppResult {
    build_bitcoin(
        git_ref,
        &[
            &format!("-DCMAKE_C_COMPILER=clang-{LLVM_VERSION}"),
            &format!("-DCMAKE_CXX_COMPILER=clang++-{LLVM_VERSION}"),
            "-DBUILD_FOR_FUZZING=ON",
            &format!("-DSANITIZERS={sanitizer}"),
        ],
    )
}

fn build_bitcoin(git_ref: &str, cmake_args: &[&str]) -> AppResult {
    if !Command::new("git")
        .current_dir(BITCOIN_PATH)
        .args([
            "fetch",
            "--depth=1",
            "--refmap=refs/tags/*:refs/tags/*",
            "origin",
            git_ref,
        ])
        .status()
        .map_err(|e| format!("failed to spawn git fetch: {e}"))?
        .success()
    {
        return Err(format!("git fetch {git_ref} failed"));
    }

    if !Command::new("git")
        .current_dir(BITCOIN_PATH)
        .args(["checkout", "FETCH_HEAD"])
        .status()
        .map_err(|e| format!("failed to spawn git checkout: {e}"))?
        .success()
    {
        return Err(format!("git checkout {git_ref} failed"));
    }

    let build_dir = Path::new(BITCOIN_PATH).join(BITCOIN_BUILD_DIR);
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir)
            .map_err(|e| format!("failed to remove {BITCOIN_BUILD_DIR} directory: {e}"))?;
    }

    if !Command::new("cmake")
        .current_dir(BITCOIN_PATH)
        .env("LDFLAGS", "-fuse-ld=lld")
        .args(["-B", BITCOIN_BUILD_DIR])
        .args(cmake_args)
        .status()
        .map_err(|e| format!("failed to run cmake configure: {e}"))?
        .success()
    {
        return Err("CMake configuration failed".to_string());
    }

    if !Command::new("cmake")
        .current_dir(BITCOIN_PATH)
        .args(["--build", BITCOIN_BUILD_DIR, &format!("-j{}", nproc())])
        .status()
        .map_err(|e| format!("failed to build with cmake: {e}"))?
        .success()
    {
        return Err("CMake build failed".to_string());
    }

    Ok(())
}

fn get_fuzz_targets() -> Result<Vec<String>, AppError> {
    let out_path = "/tmp/fuzz_targets";
    if !Command::new(format!("{BITCOIN_BUILD_DIR}/bin/fuzz"))
        .env("WRITE_ALL_FUZZ_TARGETS_AND_ABORT", out_path)
        .current_dir(BITCOIN_PATH)
        .status()
        .map_err(|e| format!("failed to write fuzz targets: {e}"))?
        .success()
    {
        return Err("failed to write fuzz targets".to_string());
    }
    let file =
        fs::File::open(out_path).map_err(|e| format!("could not open file {}: {e}", out_path))?;

    let mut fuzz_targets = Vec::new();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.map_err(|e| format!("could not read line in fuzz targets file: {e}"))?;
        let line = line.trim();
        if !line.is_empty() {
            fuzz_targets.push(line.to_owned());
        }
    }
    Ok(fuzz_targets)
}

/// Minimize the inputs of every fuzz target and add the result to `fuzz_corpora_dir`.
fn add_minimized_inputs(
    all_inputs_dir: &Path,
    fuzz_corpora_dir: &Path,
    minimizer: &Minimizer,
) -> AppResult {
    let mut fuzz_targets = Vec::new();
    for fuzz_target in get_fuzz_targets()? {
        if all_inputs_dir.join(&fuzz_target).is_dir() {
            fuzz_targets.push(fuzz_target);
        } else {
            println!("No input corpus for {fuzz_target} (ignoring)");
        }
    }

    let next = AtomicUsize::new(0);
    let work = || -> AppResult {
        while let Some(fuzz_target) = fuzz_targets.get(next.fetch_add(1, Ordering::Relaxed)) {
            println!("Minimizing {fuzz_target} with {}", minimizer.name);
            let output_dir = Path::new(MINIMIZED_DIR).join(fuzz_target);
            (minimizer.minimize)(fuzz_target, &all_inputs_dir.join(fuzz_target), &output_dir)?;
            move_files(&output_dir, &fuzz_corpora_dir.join(fuzz_target))?;
        }
        Ok(())
    };
    thread::scope(|s| {
        let workers: Vec<_> = (0..minimizer.jobs).map(|_| s.spawn(work)).collect();
        workers
            .into_iter()
            .try_for_each(|w| w.join().expect("minimizer thread panicked"))
    })
}

fn run_afl_cmin(fuzz_target: &str, input_dir: &Path, output_dir: &Path) -> AppResult {
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir for afl-cmin: {e}"))?;

    if !Command::new("afl-cmin")
        .env("FUZZ", fuzz_target)
        .args([
            "-T",
            "all",
            "-A",
            "-t",
            &(MINIMIZER_TIMEOUT_SECS * 1000).to_string(),
            "-i",
            &input_dir.display().to_string(),
            "-o",
            &output_dir.display().to_string(),
            "--",
            &format!("{BITCOIN_PATH}/{BITCOIN_BUILD_DIR}/bin/fuzz"),
        ])
        .status()
        .map_err(|e| format!("failed to spawn afl-cmin: {e}"))?
        .success()
    {
        return Err(format!("afl-cmin failed for {fuzz_target}"));
    }
    Ok(())
}

fn run_honggfuzz_minimize(fuzz_target: &str, input_dir: &Path, output_dir: &Path) -> AppResult {
    let kept_dir = Path::new(HONGGFUZZ_OUTPUT_DIR).join(fuzz_target);
    // honggfuzz only creates the last component of its output dir
    fs::create_dir_all(&kept_dir)
        .map_err(|e| format!("failed to create output dir for honggfuzz: {e}"))?;

    if !Command::new("honggfuzz")
        .env("FUZZ", fuzz_target)
        .args([
            "--minimize",
            // Plain log lines instead of the interactive screen, warnings and errors only
            "--verbose",
            "--quiet",
            &format!("--timeout={MINIMIZER_TIMEOUT_SECS}"),
            "--input",
            &input_dir.display().to_string(),
            "--output",
            &kept_dir.display().to_string(),
            "--",
            &format!("{BITCOIN_PATH}/{BITCOIN_BUILD_DIR}/bin/fuzz"),
        ])
        .status()
        .map_err(|e| format!("failed to spawn honggfuzz: {e}"))?
        .success()
    {
        return Err(format!("honggfuzz failed for {fuzz_target}"));
    }

    copy_kept_inputs(&kept_dir, input_dir, output_dir)?;
    fs::remove_dir_all(&kept_dir)
        .map_err(|e| format!("failed to remove {}: {e}", kept_dir.display()))
}

/// Copy to `output_dir` the inputs that the files honggfuzz kept in `kept_dir` come from.
///
/// honggfuzz also runs the first 4, 8, 16, ... bytes of each input and may keep such a prefix.
/// It is replaced by the smallest input starting with it, which makes honggfuzz run it again.
fn copy_kept_inputs(kept_dir: &Path, input_dir: &Path, output_dir: &Path) -> AppResult {
    let mut inputs = read_files(input_dir)?;
    inputs.sort_by(|(name_a, a), (name_b, b)| (a.len(), name_a).cmp(&(b.len(), name_b)));

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create {}: {e}", output_dir.display()))?;
    for (kept_name, kept) in read_files(kept_dir)? {
        let is_run_prefix = kept.len() >= 4 && kept.len().is_power_of_two();
        let (name, _) = inputs
            .iter()
            .find(|(_, input)| {
                input.starts_with(&kept) && (input.len() == kept.len() || is_run_prefix)
            })
            .ok_or_else(|| {
                format!(
                    "honggfuzz kept {}, which is neither an input nor a prefix it runs",
                    kept_dir.join(&kept_name).display()
                )
            })?;
        let (from, to) = (input_dir.join(name), output_dir.join(name));
        fs::copy(&from, &to)
            .map_err(|e| format!("failed to copy {} to {}: {e}", from.display(), to.display()))?;
    }
    Ok(())
}

fn read_files(dir: &Path) -> Result<Vec<(OsString, Vec<u8>)>, AppError> {
    fs::read_dir(dir)
        .map_err(|e| format!("failed to read {}: {e}", dir.display()))?
        .map(|entry| {
            let entry =
                entry.map_err(|e| format!("failed to read entry in {}: {e}", dir.display()))?;
            let content = fs::read(entry.path())
                .map_err(|e| format!("failed to read {}: {e}", entry.path().display()))?;
            Ok((entry.file_name(), content))
        })
        .collect()
}

/// Move every file in `src` into `dst`, and remove `src`.
fn move_files(src: &Path, dst: &Path) -> AppResult {
    let names: Vec<OsString> = fs::read_dir(src)
        .map_err(|e| format!("failed to read {}: {e}", src.display()))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("failed to read entry in {}: {e}", src.display()))?;

    fs::create_dir_all(dst).map_err(|e| format!("failed to create {}: {e}", dst.display()))?;
    for name in names {
        let (from, to) = (src.join(&name), dst.join(&name));
        fs::rename(&from, &to)
            .map_err(|e| format!("failed to move {} to {}: {e}", from.display(), to.display()))?;
    }

    // Not fs::remove_dir, as src might not be empty: afl-cmin creates hard links, and renaming
    // onto another link of the same inode succeeds as a no-op.
    fs::remove_dir_all(src).map_err(|e| format!("failed to remove {}: {e}", src.display()))
}

fn run_libfuzzer<P: AsRef<Path>, Q: AsRef<Path>>(input_dir: P, output_dir: Q) -> AppResult {
    // test_runner.py uses libFuzzer
    if !Command::new(format!(
        "{BITCOIN_PATH}/{BITCOIN_BUILD_DIR}/test/fuzz/test_runner.py"
    ))
    .args([
        "-l=DEBUG",
        &format!("--par={}", nproc()),
        &format!("--m_dir={}", input_dir.as_ref().display()),
        &format!("{}", output_dir.as_ref().display()),
    ])
    .status()
    .map_err(|e| format!("failed to spawn test_runner.py: {e}"))?
    .success()
    {
        return Err("test_runner.py failed".to_string());
    }
    Ok(())
}

fn nproc() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn main() -> ExitCode {
    match app() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("⚠️\n{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_files(dir: &Path, files: &[(&str, &str)]) {
        fs::create_dir_all(dir).unwrap();
        for (name, content) in files {
            fs::write(dir.join(name), content).unwrap();
        }
    }

    fn sorted_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn copy_kept_inputs_replaces_prefixes() {
        let root = test_dir("copy-kept-inputs");
        let (kept, inputs, out) = (root.join("kept"), root.join("in"), root.join("out"));
        write_files(
            &inputs,
            &[
                ("long", "abcdefgh-long"),
                ("longer", "abcdefgh-longer"),
                ("short", "xy"),
                ("unused", "unused"),
            ],
        );
        // An 8 byte prefix of two inputs, and a whole input
        write_files(&kept, &[("prefix", "abcdefgh"), ("whole", "xy")]);

        copy_kept_inputs(&kept, &inputs, &out).unwrap();

        assert_eq!(sorted_names(&out), ["long", "short"]);
        assert_eq!(fs::read(out.join("long")).unwrap(), b"abcdefgh-long");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn copy_kept_inputs_rejects_unknown_files() {
        let root = test_dir("copy-kept-inputs-unknown");
        let (kept, inputs, out) = (root.join("kept"), root.join("in"), root.join("out"));
        write_files(&inputs, &[("input", "abcdefgh-long")]);
        // Prefixes honggfuzz doesn't run, and an unrelated file
        for content in ["abcdef", "ab", "unrelated"] {
            write_files(&kept, &[("kept", content)]);
            assert!(copy_kept_inputs(&kept, &inputs, &out).is_err());
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn move_files_merges_into_dst() {
        let root = test_dir("move-files");
        let (src, dst) = (root.join("src"), root.join("dst"));
        write_files(&dst, &[("old", "old")]);
        write_files(&src, &[("new", "new")]);
        // afl-cmin hard links its output to the inputs, of which dst may hold another link
        fs::hard_link(dst.join("old"), src.join("old")).unwrap();

        move_files(&src, &dst).unwrap();

        assert_eq!(sorted_names(&dst), ["new", "old"]);
        assert!(!src.exists());
        fs::remove_dir_all(&root).unwrap();
    }
}
