use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use comment_policy::{
    FileRole, ViolationKind, allowed_docs, check_workspace, scan_comments, violations_in,
};

fn check(source: &str, role: FileRole) -> Vec<(usize, ViolationKind)> {
    let (allowed, _) = allowed_docs(source, Path::new("src/lib.rs"), role).unwrap();
    violations_in(source, Path::new("src/lib.rs"), &allowed)
        .into_iter()
        .map(|v| (v.line, v.kind))
        .collect()
}

#[test]
fn a_line_or_block_comment_is_refused_anywhere() {
    let source = "pub fn a() {\n    // why\n    let _x = 1; /* also */\n}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![(2, ViolationKind::Comment), (3, ViolationKind::Comment)]
    );
}

#[test]
fn docs_on_a_public_item_are_allowed_and_on_a_private_one_refused() {
    let source = "/// ok\npub fn a() {}\n/// no\nfn b() {}\n/// no\npub(crate) fn c() {}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![
            (3, ViolationKind::PrivateDoc),
            (5, ViolationKind::PrivateDoc)
        ]
    );
}

#[test]
fn a_public_item_inside_a_private_module_is_not_public() {
    let source = "mod inner {\n    /// no\n    pub fn a() {}\n}\npub mod open {\n    /// ok\n    pub fn b() {}\n}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![(2, ViolationKind::PrivateDoc)]
    );
}

#[test]
fn variants_fields_and_trait_items_follow_their_parent() {
    let source = "/// ok\npub enum E {\n    /// ok\n    A,\n}\n/// ok\npub struct S {\n    /// ok\n    pub a: u8,\n    /// no\n    b: u8,\n}\n/// ok\npub trait T {\n    /// ok\n    fn f(&self);\n}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![(10, ViolationKind::PrivateDoc)]
    );
}

#[test]
fn trait_impl_items_carry_no_docs_but_inherent_public_methods_may() {
    let source = "pub struct S;\nimpl S {\n    /// ok\n    pub fn a(&self) {}\n    /// no\n    fn b(&self) {}\n}\nimpl Clone for S {\n    /// no\n    fn clone(&self) -> S { S }\n}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![
            (5, ViolationKind::PrivateDoc),
            (9, ViolationKind::PrivateDoc)
        ]
    );
}

#[test]
fn inner_docs_are_allowed_on_a_public_crate_root_only() {
    let source = "//! crate docs\npub fn a() {}\n";
    assert!(check(source, FileRole::PublicCrateRoot).is_empty());
    assert_eq!(
        check(source, FileRole::PrivateCrateRoot),
        vec![(1, ViolationKind::PrivateDoc)]
    );
    assert_eq!(
        check(source, FileRole::Module { public: false }),
        vec![(1, ViolationKind::PrivateDoc)]
    );
}

#[test]
fn tests_are_private_code() {
    let source = "#[cfg(test)]\nmod tests {\n    /// no\n    #[test]\n    fn t() {}\n}\n";
    assert_eq!(
        check(source, FileRole::PublicCrateRoot),
        vec![(3, ViolationKind::PrivateDoc)]
    );
}

#[test]
fn comment_markers_inside_strings_chars_and_raw_strings_are_not_comments() {
    let source = "pub fn a<'a>(x: &'a str) -> [&'a str; 4] {\n    let _c = '/';\n    let _q = '\\'';\n    [\"http://x\", r#\"/* \"no\" */\"#, b\"//\".len().to_string().leak(), x]\n}\n";
    assert!(
        scan_comments(source).is_empty(),
        "{:?}",
        scan_comments(source)
    );
}

#[test]
fn a_block_comment_spanning_lines_keeps_later_line_numbers_right() {
    let source = "/*\n\n*/\nfn a() {}\n// here\n";
    let lines: Vec<usize> = scan_comments(source).iter().map(|c| c.line).collect();
    assert_eq!(lines, vec![1, 5]);
}

#[test]
fn four_slashes_and_empty_block_docs_are_plain_comments() {
    let docs: Vec<bool> = scan_comments("//// x\n/**/\n/*** x */\n/// y\n//! z\n")
        .iter()
        .map(|c| c.doc)
        .collect();
    assert_eq!(docs, vec![false, false, false, true, true]);
}

#[test]
fn a_mod_declaration_is_followed_with_its_visibility() {
    let (_, children) = allowed_docs(
        "pub mod a;\nmod b;\n",
        Path::new("src/lib.rs"),
        FileRole::PublicCrateRoot,
    )
    .unwrap();
    let publics: BTreeSet<(PathBuf, bool)> =
        children.into_iter().map(|c| (c.path, c.public)).collect();
    assert!(publics.contains(&(PathBuf::from("src/a/mod.rs"), true)));
    assert!(publics.contains(&(PathBuf::from("src/b/mod.rs"), false)));
}

#[test]
fn this_workspace_follows_the_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let violations = check_workspace(&root).unwrap();
    let report: Vec<String> = violations.iter().map(ToString::to_string).collect();
    assert!(
        violations.is_empty(),
        "{} refused:\n{}",
        report.len(),
        report.join("\n")
    );
}
