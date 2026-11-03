//! Mapping from a [`LanguageId`] to a compiled tree-sitter grammar.
//!
//! Each grammar lives behind a `lang-*` cargo feature so a deployment only
//! links the languages it actually scans. Adding a language means adding one
//! arm here and one feature in `Cargo.toml`; nothing else in the workspace
//! changes.

use astrix_core::{AstrixError, LanguageId, Result};
use tree_sitter::Language;

/// Loads the compiled grammar for `language`.
///
/// # Errors
///
/// Returns [`AstrixError::UnsupportedLanguage`] when the grammar for
/// `language` was not compiled into this build.
pub fn load(language: LanguageId) -> Result<Language> {
    match language {
        #[cfg(feature = "lang-python")]
        LanguageId::Python => Ok(tree_sitter_python::LANGUAGE.into()),
        #[cfg(feature = "lang-javascript")]
        LanguageId::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
        other => Err(AstrixError::UnsupportedLanguage(other)),
    }
}

/// Languages whose grammars are available in this build, in a stable order.
pub fn supported() -> Vec<LanguageId> {
    LanguageId::ALL.iter().copied().filter(|lang| load(*lang).is_ok()).collect()
}

/// Returns `true` when this build can parse `language`.
pub fn is_supported(language: LanguageId) -> bool {
    load(language).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{is_supported, supported};
    use astrix_core::LanguageId;

    #[test]
    fn unsupported_languages_are_reported_rather_than_panicking() {
        assert!(!is_supported(LanguageId::Go));
        assert!(super::load(LanguageId::Go).is_err());
    }

    #[cfg(feature = "lang-python")]
    #[test]
    fn python_is_available_behind_its_feature() {
        assert!(is_supported(LanguageId::Python));
        assert!(supported().contains(&LanguageId::Python));
    }

    #[test]
    fn supported_order_is_stable() {
        assert_eq!(supported(), supported());
    }
}
