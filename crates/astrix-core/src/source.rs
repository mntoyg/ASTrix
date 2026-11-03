//! The immutable source buffer every span is resolved against.

use std::path::{Path, PathBuf};

use crate::error::{AstrixError, Result};
use crate::language::LanguageId;
use crate::span::{ByteSpan, Point, SourceSpan};

/// An immutable, language-tagged source buffer with a precomputed line index.
///
/// `SourceFile` is the single source of truth a rewrite is computed against.
/// It is never mutated: [`crate::AstMutator`] consumes a `SourceFile` plus an
/// [`crate::EditScript`] and produces a brand-new [`crate::Patch`], so the
/// spans a rule reported stay valid for the whole pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    path: PathBuf,
    language: LanguageId,
    text: String,
    line_starts: Vec<usize>,
}

impl SourceFile {
    /// Creates a source file from text already held in memory.
    pub fn new(path: impl Into<PathBuf>, language: LanguageId, text: impl Into<String>) -> Self {
        let text = text.into();
        let line_starts = line_starts(&text);
        Self { path: path.into(), language, text, line_starts }
    }

    /// Reads a file from disk, inferring the language from its extension.
    pub fn read(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let language = LanguageId::from_path(&path).ok_or_else(|| AstrixError::Parse {
            path: path.clone(),
            reason: "unrecognised file extension".to_owned(),
        })?;
        let text = std::fs::read_to_string(&path)
            .map_err(|source| AstrixError::Io { path: path.clone(), source })?;
        Ok(Self::new(path, language, text))
    }

    /// Path this buffer came from, used for diagnostics and patch provenance.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Language tag driving backend and rule selection.
    pub fn language(&self) -> LanguageId {
        self.language
    }

    /// Full text of the buffer.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Full text of the buffer as bytes, which is what parser backends consume.
    pub fn bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// Length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns `true` when the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Number of lines in the buffer.
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Validates that `span` is in bounds and lands on character boundaries.
    pub fn validate_span(&self, span: ByteSpan) -> Result<()> {
        if span.end > self.text.len() {
            return Err(AstrixError::SpanOutOfBounds { span, length: self.text.len() });
        }
        if !self.text.is_char_boundary(span.start) || !self.text.is_char_boundary(span.end) {
            return Err(AstrixError::NotCharBoundary { span });
        }
        Ok(())
    }

    /// Returns the text covered by `span`, or `None` if the span is invalid.
    pub fn try_slice(&self, span: ByteSpan) -> Option<&str> {
        self.text.get(span.start..span.end)
    }

    /// Returns the text covered by `span`.
    ///
    /// # Panics
    ///
    /// Panics if the span is out of bounds or splits a character. Use
    /// [`SourceFile::try_slice`] when the span came from an untrusted source;
    /// spans produced by a parser backend are always valid here.
    pub fn slice(&self, span: ByteSpan) -> &str {
        self.try_slice(span).expect("span must be a valid character-aligned range")
    }

    /// Converts a byte offset into a zero-based row/column [`Point`].
    pub fn point_at(&self, offset: usize) -> Point {
        let row = match self.line_starts.binary_search(&offset) {
            Ok(exact) => exact,
            Err(insert) => insert.saturating_sub(1),
        };
        Point::new(row, offset - self.line_starts[row])
    }

    /// Enriches a byte range with the row/column positions of its endpoints.
    pub fn source_span(&self, span: ByteSpan) -> SourceSpan {
        SourceSpan::new(span, self.point_at(span.start), self.point_at(span.end))
    }

    /// Byte span of `row`, excluding its line terminator.
    pub fn line_span(&self, row: usize) -> Option<ByteSpan> {
        let start = *self.line_starts.get(row)?;
        let end =
            self.line_starts.get(row + 1).map_or(self.text.len(), |next| next.saturating_sub(1));
        Some(ByteSpan::new(start, end.max(start)))
    }

    /// Text of `row`, excluding its line terminator.
    pub fn line(&self, row: usize) -> Option<&str> {
        self.line_span(row).and_then(|span| self.try_slice(span))
    }

    /// Returns the same buffer with `text` swapped in, keeping path and language.
    ///
    /// Used to re-parse a rewritten candidate before it reaches the
    /// zero-breakage gate.
    pub fn with_text(&self, text: impl Into<String>) -> Self {
        Self::new(self.path.clone(), self.language, text)
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(text.len() / 32 + 1);
    starts.push(0);
    starts.extend(
        text.bytes().enumerate().filter(|(_, byte)| *byte == b'\n').map(|(index, _)| index + 1),
    );
    starts
}

#[cfg(test)]
mod tests {
    use super::SourceFile;
    use crate::language::LanguageId;
    use crate::span::{ByteSpan, Point};

    fn fixture() -> SourceFile {
        SourceFile::new("app/main.py", LanguageId::Python, "import yaml\ncfg = load(x)\n")
    }

    #[test]
    fn point_lookup_matches_line_offsets() {
        let source = fixture();
        assert_eq!(source.point_at(0), Point::new(0, 0));
        assert_eq!(source.point_at(7), Point::new(0, 7));
        assert_eq!(source.point_at(12), Point::new(1, 0));
        assert_eq!(source.line_count(), 3);
    }

    #[test]
    fn lines_exclude_their_terminator() {
        let source = fixture();
        assert_eq!(source.line(0), Some("import yaml"));
        assert_eq!(source.line(1), Some("cfg = load(x)"));
        assert_eq!(source.line(2), Some(""));
        assert_eq!(source.line(3), None);
    }

    #[test]
    fn span_validation_rejects_out_of_bounds_ranges() {
        let source = fixture();
        assert!(source.validate_span(ByteSpan::new(0, 11)).is_ok());
        assert!(source.validate_span(ByteSpan::new(0, 9_000)).is_err());
    }

    #[test]
    fn multi_byte_characters_are_not_split() {
        let source = SourceFile::new("t.py", LanguageId::Python, "x = \"ค่า\"\n");
        let inside_thai_character = ByteSpan::new(0, 6);
        assert!(source.validate_span(inside_thai_character).is_err());
    }
}
