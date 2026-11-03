//! Language identity, independent of any particular parser backend.

use core::fmt;
use std::path::Path;

/// A source language ASTrix can reason about.
///
/// The enum is `#[non_exhaustive]`: adding a language is a minor, non-breaking
/// change, and downstream matches are required to carry a fallback arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LanguageId {
    /// Python 3.
    Python,
    /// ECMAScript / JavaScript.
    JavaScript,
    /// TypeScript.
    TypeScript,
    /// Go.
    Go,
    /// Java.
    Java,
    /// Rust.
    Rust,
}

impl LanguageId {
    /// Every language the enum currently knows about, in a stable order.
    pub const ALL: &'static [Self] =
        &[Self::Python, Self::JavaScript, Self::TypeScript, Self::Go, Self::Java, Self::Rust];

    /// Stable lowercase identifier, used in rule metadata and fixture manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
            Self::Java => "java",
            Self::Rust => "rust",
        }
    }

    /// Canonical file extension for the language.
    pub const fn primary_extension(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::JavaScript => "js",
            Self::TypeScript => "ts",
            Self::Go => "go",
            Self::Java => "java",
            Self::Rust => "rs",
        }
    }

    /// Parses the identifier produced by [`LanguageId::as_str`].
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|lang| lang.as_str() == name)
    }

    /// Infers the language from a file extension, ignoring a leading dot.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.trim_start_matches('.') {
            "py" | "pyi" => Some(Self::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(Self::JavaScript),
            "ts" | "mts" | "cts" | "tsx" => Some(Self::TypeScript),
            "go" => Some(Self::Go),
            "java" => Some(Self::Java),
            "rs" => Some(Self::Rust),
            _ => None,
        }
    }

    /// Infers the language from a path's extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension().and_then(|ext| ext.to_str()).and_then(Self::from_extension)
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::LanguageId;
    use std::path::Path;

    #[test]
    fn name_round_trips_for_every_language() {
        for lang in LanguageId::ALL {
            assert_eq!(LanguageId::from_name(lang.as_str()), Some(*lang));
        }
    }

    #[test]
    fn primary_extension_resolves_back_to_its_language() {
        for lang in LanguageId::ALL {
            assert_eq!(LanguageId::from_extension(lang.primary_extension()), Some(*lang));
        }
    }

    #[test]
    fn path_inference_handles_unknown_extensions() {
        assert_eq!(LanguageId::from_path(Path::new("app/main.py")), Some(LanguageId::Python));
        assert_eq!(LanguageId::from_path(Path::new("README.md")), None);
    }
}
