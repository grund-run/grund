//! The comment policy of this repository: in Rust, the only comments are
//! documentation on public items (Kasper, 2026-09-24).
//!
//! A `//` or `/* */` comment anywhere is refused. A doc comment (`///`,
//! `//!`, `/** */`, `/*! */`) is allowed only on an item declared `pub` whose
//! enclosing modules are all `pub`, on the variants and fields of such an
//! item, on the items of such a trait, and as the inner documentation of a
//! `lib.rs`, `main.rs` or `src/bin/*.rs` crate root. Everything else, private
//! code and tests included, explains itself through names or in commit bodies.
//!
//! Visibility is syntactic: `pub(crate)` is not public, and a `pub` item in a
//! private module is not either. Items in `impl Trait for T` blocks never
//! carry docs; the trait's documentation is what rustdoc shows.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::Context;
use syn::spanned::Spanned;

/// One comment the policy refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: PathBuf,
    pub line: usize,
    pub kind: ViolationKind,
}

/// Why a comment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// A `//` or `/* */` comment.
    Comment,
    /// Documentation on something that is not public.
    PrivateDoc,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.kind {
            ViolationKind::Comment => {
                "comment: only doc comments on public items are allowed; say it in a name, a public item's docs or the commit body"
            }
            ViolationKind::PrivateDoc => {
                "doc comment on an item that is not public: make the item public API or drop the comment"
            }
        };
        write!(f, "{}:{}: {what}", self.path.display(), self.line)
    }
}

/// A comment found by [`scan_comments`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comment {
    pub line: usize,
    pub doc: bool,
}

/// Every comment in `source`, in order. Strings, raw strings, byte strings
/// and character literals are skipped, so `"http://x"` is not a comment and
/// a lifetime is not a character literal.
pub fn scan_comments(source: &str) -> Vec<Comment> {
    let bytes = source.as_bytes();
    let mut comments = Vec::new();
    let mut line = 1;
    let mut i = 0;
    let count_lines =
        |from: usize, to: usize| bytes[from..to].iter().filter(|&&b| b == b'\n').count();
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let rest = &bytes[i..];
                let doc = (rest.starts_with(b"///") && !rest.starts_with(b"////"))
                    || rest.starts_with(b"//!");
                comments.push(Comment { line, doc });
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let rest = &bytes[i..];
                let doc = (rest.starts_with(b"/**")
                    && !rest.starts_with(b"/***")
                    && !rest.starts_with(b"/**/"))
                    || rest.starts_with(b"/*!");
                comments.push(Comment { line, doc });
                let start = i;
                let mut depth = 0usize;
                while i < bytes.len() {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                line += count_lines(start, i.min(bytes.len()));
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                line += count_lines(start, i.min(bytes.len()));
            }
            b'r' if raw_string_start(bytes, i) => {
                let start = i;
                i += 1;
                let mut hashes = 0;
                while bytes.get(i) == Some(&b'#') {
                    hashes += 1;
                    i += 1;
                }
                i += 1;
                let mut close = vec![b'"'];
                close.extend(std::iter::repeat_n(b'#', hashes));
                while i < bytes.len() && !bytes[i..].starts_with(&close) {
                    i += 1;
                }
                i += close.len();
                line += count_lines(start, i.min(bytes.len()));
            }
            b'\'' => {
                if bytes.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                } else if let Some(width) = source[i + 1..].chars().next().map(char::len_utf8)
                    && bytes.get(i + 1 + width) == Some(&b'\'')
                {
                    i += width + 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    comments
}

fn raw_string_start(bytes: &[u8], i: usize) -> bool {
    let preceded_by_ident = i > 0 && {
        let before = bytes[i - 1];
        (before.is_ascii_alphanumeric() || before == b'_') && !matches!(before, b'b' | b'c')
            || (matches!(before, b'b' | b'c')
                && i > 1
                && (bytes[i - 2].is_ascii_alphanumeric() || bytes[i - 2] == b'_'))
    };
    if preceded_by_ident {
        return false;
    }
    let mut j = i + 1;
    while bytes.get(j) == Some(&b'#') {
        j += 1;
    }
    bytes.get(j) == Some(&b'"')
}

/// What kind of file a source is, which decides whether its inner docs
/// (`//!`) are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRole {
    /// `lib.rs`, `main.rs` or `src/bin/*.rs`: the crate is public.
    PublicCrateRoot,
    /// `build.rs` or an integration test: nothing in it is public.
    PrivateCrateRoot,
    /// A module file, public when every `mod` leading to it is `pub`.
    Module { public: bool },
}

/// A module file named by a `mod` declaration, to check next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildModule {
    pub path: PathBuf,
    pub public: bool,
}

/// The lines of doc comments in one file that the policy allows, and the
/// module files it declares.
pub fn allowed_docs(
    source: &str,
    file: &Path,
    role: FileRole,
) -> Result<(BTreeSet<usize>, Vec<ChildModule>), syn::Error> {
    let parsed = syn::parse_file(source)?;
    let mut walker = Walker {
        allowed: BTreeSet::new(),
        children: Vec::new(),
    };
    let public = match role {
        FileRole::PublicCrateRoot => true,
        FileRole::PrivateCrateRoot => false,
        FileRole::Module { public } => public,
    };
    if public {
        walker.allow(&parsed.attrs);
    }
    let dir = module_dir(file, role);
    walker.items(
        &parsed.items,
        public,
        &dir,
        file.parent().unwrap_or(Path::new("")),
    );
    Ok((walker.allowed, walker.children))
}

fn module_dir(file: &Path, role: FileRole) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new("")).to_path_buf();
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    match role {
        FileRole::Module { .. } if name != "mod.rs" => parent.join(
            file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default(),
        ),
        _ => parent,
    }
}

struct Walker {
    allowed: BTreeSet<usize>,
    children: Vec<ChildModule>,
}

impl Walker {
    fn allow(&mut self, attrs: &[syn::Attribute]) {
        for attr in attrs.iter().filter(|a| a.path().is_ident("doc")) {
            let span = attr.span();
            for line in span.start().line..=span.end().line {
                self.allowed.insert(line);
            }
        }
    }

    fn allow_if(&mut self, allowed: bool, attrs: &[syn::Attribute]) {
        if allowed {
            self.allow(attrs);
        }
    }

    fn fields(&mut self, parent: bool, fields: &syn::Fields) {
        for field in fields {
            self.allow_if(parent && is_pub(&field.vis), &field.attrs);
        }
    }

    fn items(&mut self, items: &[syn::Item], public: bool, dir: &Path, file_dir: &Path) {
        for item in items {
            match item {
                syn::Item::Fn(i) => self.allow_if(public && is_pub(&i.vis), &i.attrs),
                syn::Item::Const(i) => self.allow_if(public && is_pub(&i.vis), &i.attrs),
                syn::Item::Static(i) => self.allow_if(public && is_pub(&i.vis), &i.attrs),
                syn::Item::Type(i) => self.allow_if(public && is_pub(&i.vis), &i.attrs),
                syn::Item::Use(i) => self.allow_if(public && is_pub(&i.vis), &i.attrs),
                syn::Item::Struct(i) => {
                    let allowed = public && is_pub(&i.vis);
                    self.allow_if(allowed, &i.attrs);
                    self.fields(allowed, &i.fields);
                }
                syn::Item::Union(i) => {
                    let allowed = public && is_pub(&i.vis);
                    self.allow_if(allowed, &i.attrs);
                    for field in &i.fields.named {
                        self.allow_if(allowed && is_pub(&field.vis), &field.attrs);
                    }
                }
                syn::Item::Enum(i) => {
                    let allowed = public && is_pub(&i.vis);
                    self.allow_if(allowed, &i.attrs);
                    for variant in &i.variants {
                        self.allow_if(allowed, &variant.attrs);
                        self.fields(allowed, &variant.fields);
                    }
                }
                syn::Item::Trait(i) => {
                    let allowed = public && is_pub(&i.vis);
                    self.allow_if(allowed, &i.attrs);
                    for trait_item in &i.items {
                        let attrs = match trait_item {
                            syn::TraitItem::Fn(t) => &t.attrs,
                            syn::TraitItem::Const(t) => &t.attrs,
                            syn::TraitItem::Type(t) => &t.attrs,
                            syn::TraitItem::Macro(t) => &t.attrs,
                            _ => continue,
                        };
                        self.allow_if(allowed, attrs);
                    }
                }
                syn::Item::Impl(i) if i.trait_.is_none() => {
                    for impl_item in &i.items {
                        let (vis, attrs) = match impl_item {
                            syn::ImplItem::Fn(t) => (&t.vis, &t.attrs),
                            syn::ImplItem::Const(t) => (&t.vis, &t.attrs),
                            syn::ImplItem::Type(t) => (&t.vis, &t.attrs),
                            _ => continue,
                        };
                        self.allow_if(public && is_pub(vis), attrs);
                    }
                }
                syn::Item::Macro(i) => {
                    let exported = i.attrs.iter().any(|a| a.path().is_ident("macro_export"));
                    self.allow_if(exported, &i.attrs);
                }
                syn::Item::Mod(i) => {
                    let allowed = public && is_pub(&i.vis);
                    self.allow_if(allowed, &i.attrs);
                    let name = i.ident.to_string();
                    match &i.content {
                        Some((_, items)) => {
                            self.items(items, allowed, &dir.join(&name), file_dir);
                        }
                        None => {
                            let path = path_attr(&i.attrs)
                                .map(|p| file_dir.join(p))
                                .unwrap_or_else(|| {
                                    let flat = dir.join(format!("{name}.rs"));
                                    if flat.exists() {
                                        flat
                                    } else {
                                        dir.join(&name).join("mod.rs")
                                    }
                                });
                            self.children.push(ChildModule {
                                path,
                                public: allowed,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.path().is_ident("path"))
        .and_then(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        })
}

/// Checks one file: every non-doc comment, and every doc comment on a line
/// `allowed` does not contain.
pub fn violations_in(source: &str, path: &Path, allowed: &BTreeSet<usize>) -> Vec<Violation> {
    scan_comments(source)
        .into_iter()
        .filter_map(|comment| {
            let kind = if !comment.doc {
                ViolationKind::Comment
            } else if allowed.contains(&comment.line) {
                return None;
            } else {
                ViolationKind::PrivateDoc
            };
            Some(Violation {
                path: path.to_path_buf(),
                line: comment.line,
                kind,
            })
        })
        .collect()
}

/// Checks every Rust file of every package under `crates/`, `ee/` and `tools/`,
/// starting from each crate root and following `mod` declarations. A file
/// no root reaches is checked as private.
pub fn check_workspace(root: &Path) -> anyhow::Result<Vec<Violation>> {
    let mut violations = Vec::new();
    let mut visited = BTreeSet::new();
    let mut all_files = Vec::new();
    for group in ["crates", "ee", "tools"] {
        let Ok(entries) = std::fs::read_dir(root.join(group)) else {
            continue;
        };
        for package in entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join("Cargo.toml").exists())
        {
            collect_rust_files(&package, &mut all_files)?;
            let mut roots: Vec<(PathBuf, FileRole)> = Vec::new();
            for (file, role) in [
                (package.join("src/lib.rs"), FileRole::PublicCrateRoot),
                (package.join("src/main.rs"), FileRole::PublicCrateRoot),
                (package.join("build.rs"), FileRole::PrivateCrateRoot),
            ] {
                if file.exists() {
                    roots.push((file, role));
                }
            }
            for (dir, role) in [
                (package.join("src/bin"), FileRole::PublicCrateRoot),
                (package.join("tests"), FileRole::PrivateCrateRoot),
            ] {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for file in entries.flatten().map(|e| e.path()) {
                        if file.extension().is_some_and(|e| e == "rs") {
                            roots.push((file, role));
                        }
                    }
                }
            }
            let mut queue = roots;
            while let Some((file, role)) = queue.pop() {
                if !visited.insert(file.clone()) {
                    continue;
                }
                let source = std::fs::read_to_string(&file)
                    .with_context(|| format!("read {}", file.display()))?;
                let (allowed, children) = allowed_docs(&source, &file, role)
                    .with_context(|| format!("parse {}", file.display()))?;
                violations.extend(violations_in(&source, &relative(root, &file), &allowed));
                for child in children {
                    queue.push((
                        child.path,
                        FileRole::Module {
                            public: child.public,
                        },
                    ));
                }
            }
        }
    }
    for file in all_files.into_iter().filter(|f| !visited.contains(f)) {
        let source =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        violations.extend(violations_in(
            &source,
            &relative(root, &file),
            &BTreeSet::new(),
        ));
    }
    violations.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    Ok(violations)
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && !name.to_string_lossy().starts_with('.') {
                collect_rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, file: &Path) -> PathBuf {
    file.strip_prefix(root).unwrap_or(file).to_path_buf()
}
