use std::process::Command;

#[test]
fn reports_one_commitment_leaf_per_row_of_the_shipped_model() {
    let model = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("models/mnist-mlp.json");
    let out = Command::new(env!("CARGO_BIN_EXE_proofbench")).arg(model).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("c_tree (Z: 1024 leaves):"), "{stdout}");
    assert!(stdout.contains("freivalds 24 rounds (n=1024):") && stdout.contains("-> true"), "{stdout}");
}
