//! Compiled sedge components, page layouts, and typed form view helpers.

use std::collections::BTreeMap;
use std::sync::LazyLock;

#[rustfmt::skip]
pub mod compiled {
    include!(concat!(env!("OUT_DIR"), "/sedge.rs"));
}

pub(crate) fn compiled_css_href() -> &'static str {
    static URL: LazyLock<String> = LazyLock::new(crate::web::assets::css_href);
    &URL
}

pub(crate) fn compiled_js_href() -> &'static str {
    static URL: LazyLock<String> = LazyLock::new(crate::web::assets::js_href);
    &URL
}

pub struct ChoiceLink<'a> {
    pub key: &'a str,
    pub href: &'a str,
    pub icon: &'a str,
    pub title: &'a str,
    pub text: &'a str,
    pub sub: &'a str,
}

/// State shared by a form and its fields without copying values into component props.
pub struct FormState<'a> {
    pub csrf: &'a str,
    pub errors: &'a BTreeMap<&'static str, String>,
    pub banners: &'a BTreeMap<&'static str, String>,
}

impl FormState<'_> {
    pub fn error(&self, name: &str) -> Option<&str> {
        self.errors.get(name).map(String::as_str)
    }

    pub fn banner(&self, part: &str) -> Option<&str> {
        self.banners.get(part).map(String::as_str)
    }
}

/// Explicitly emit a boolean `data-*` attribute by presence, rather than
/// serializing its boolean value as the string `"true"` or `"false"`.
pub struct BareDataAttr(pub bool);

impl sedge_rt::StrAttr for BareDataAttr {
    fn write_str_attr(&self, out: &mut String, name: &str) {
        if self.0 {
            out.push_str(name);
        }
    }
}

pub(crate) fn short_image(reference: &str) -> String {
    match reference.split_once("@sha256:") {
        Some((name, digest)) => {
            format!(
                "{name}@sha256:{}",
                digest.chars().take(12).collect::<String>()
            )
        }
        None => reference.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_image_pinned_by_digest_shows_twelve_hex_of_it_and_a_tag_alone_is_kept() {
        let digest = "2006897904a3d1c9a8e0f5ad0e0b6d1c9c88e37d4e0a3a1f62a5a9c3ef5a1b20";
        assert_eq!(
            super::short_image(&format!("traefik/whoami:v1.11.0@sha256:{digest}")),
            "traefik/whoami:v1.11.0@sha256:2006897904a3"
        );
        assert_eq!(super::short_image("nginx:1.27"), "nginx:1.27");
    }

    #[test]
    fn every_colour_token_has_a_swatch_on_the_style_guide() {
        let css = include_str!("../assets/grund.css");
        let root = &css[css.find(":root {").expect(":root")..];
        let root = &root[..root.find('}').expect("end of :root")];
        let colours: Vec<&str> = root
            .lines()
            .filter_map(|line| line.trim().strip_prefix("--"))
            .filter(|line| line.contains('#'))
            .filter_map(|line| line.split(':').next())
            .collect();
        let shown: Vec<&str> = crate::web::pages::SWATCHES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let missing: Vec<&&str> = colours
            .iter()
            .filter(|name| !shown.contains(name))
            .collect();
        assert!(
            missing.is_empty(),
            "add these to SWATCHES and .sg-*: {missing:?}"
        );
        for name in shown {
            assert!(
                css.contains(&format!(".sg-{name} {{")),
                "no .sg-{name} rule"
            );
        }
    }
}
