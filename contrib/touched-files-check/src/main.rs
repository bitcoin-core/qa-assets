fn check(touched_files: &str) -> Result<(), String> {
    let mut only_inputs: Option<bool> = None;
    for line in touched_files.lines() {
        let (status, file) = {
            let mut l = line.split_whitespace();
            (l.next().unwrap(), l.next().unwrap())
        };
        println!("Touched file: {status} {file}");
        let fuzz_seed_corpora_dir = "fuzz_seed_corpus/";
        if only_inputs.is_none() {
            only_inputs = Some(file.starts_with(fuzz_seed_corpora_dir));
        }
        if only_inputs.unwrap() != file.starts_with(fuzz_seed_corpora_dir) {
            return Err(format!(
                "All files in this pull request should either be fuzz inputs in the directory {fuzz_seed_corpora_dir} or only files outside that dir."
            ));
        }
        if file.starts_with(fuzz_seed_corpora_dir) && status != "A" {
            return Err(format!(
                "File status for fuzz input is not 'A' (for add): '{status}' '{file}'"
            ));
        }
    }
    Ok(())
}

fn main() {
    let diff_range = std::env::args()
        .nth(1)
        .expect("Missing diff_range argument");
    let git_diff = std::process::Command::new("git")
        .args(["diff", "--no-commit-id", "--name-status", &diff_range])
        .output()
        .expect("git error");
    assert!(git_diff.status.success());
    let touched_files = String::from_utf8(git_diff.stdout).expect("Invalid utf8");
    check(&touched_files).unwrap_or_else(|e| panic!("ci check failed:\n\n{e}\n\n"));
}

#[test]
fn test_check() {
    assert_eq!(check("M README.md"), Ok(()));
    assert_eq!(
        check("B fuzz_seed_corpus/foo/bar").unwrap_err(),
        "File status for fuzz input is not 'A' (for add): 'B' 'fuzz_seed_corpus/foo/bar'",
    );
    assert_eq!(
        check("A fuzz_seed_corpus/foo/bar1\nA fuzz_seed_corpus/foo/bar2"),
        Ok(()),
    );
    assert_eq!(
        check("M README.md\nA fuzz_seed_corpus/foo/bar3").unwrap_err(),
        "All files in this pull request should either be fuzz inputs in the directory fuzz_seed_corpus/ or only files outside that dir.",
    );
}
