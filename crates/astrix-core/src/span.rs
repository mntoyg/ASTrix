//! Byte- and point-addressed source locations.
//!
//! Every span in ASTrix is a half-open byte range over the *original* source
//! buffer. Keeping the byte range authoritative (and the row/column pair
//! derived) is what makes [`crate::AstMutator`] rewrites reproducible: a span
//! never depends on how a previous edit shifted the file.

use core::fmt;

/// A half-open byte range `[start, end)` into a source buffer.
///
/// The derived [`Ord`] implementation orders by `start` first and then `end`,
/// which is the canonical ordering ASTrix uses to make edit application
/// deterministic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSpan {
    /// Inclusive start offset, in bytes.
    pub start: usize,
    /// Exclusive end offset, in bytes.
    pub end: usize,
}

impl ByteSpan {
    /// Creates a span from `start` to `end`.
    ///
    /// # Panics
    ///
    /// Panics if `end < start`, which would describe an inverted range.
    pub const fn new(start: usize, end: usize) -> Self {
        assert!(end >= start, "ByteSpan end must not precede start");
        Self { start, end }
    }

    /// Creates the empty span positioned at `offset`, used for pure insertions.
    pub const fn empty_at(offset: usize) -> Self {
        Self { start: offset, end: offset }
    }

    /// Length of the span in bytes.
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns `true` when the span covers no bytes (an insertion point).
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns `true` when `offset` falls inside the span.
    pub const fn contains(&self, offset: usize) -> bool {
        self.start <= offset && offset < self.end
    }

    /// Returns `true` when `self` fully encloses `other`.
    pub const fn encloses(&self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Returns `true` when two spans share at least one byte.
    ///
    /// Empty spans never overlap, so two insertions at the same offset — or an
    /// insertion at the boundary of a replacement — are not treated as a
    /// conflict.
    pub const fn overlaps(&self, other: Self) -> bool {
        !self.is_empty() && !other.is_empty() && self.start < other.end && other.start < self.end
    }

    /// Smallest span covering both inputs.
    pub fn union(&self, other: Self) -> Self {
        Self { start: self.start.min(other.start), end: self.end.max(other.end) }
    }
}

impl fmt::Display for ByteSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl From<core::ops::Range<usize>> for ByteSpan {
    fn from(range: core::ops::Range<usize>) -> Self {
        Self::new(range.start, range.end)
    }
}

impl From<ByteSpan> for core::ops::Range<usize> {
    fn from(span: ByteSpan) -> Self {
        span.start..span.end
    }
}

/// A zero-based row and byte-column position inside a source buffer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Point {
    /// Zero-based line index.
    pub row: usize,
    /// Zero-based byte offset from the start of the line.
    pub column: usize,
}

impl Point {
    /// Creates a point at `row` and `column`.
    pub const fn new(row: usize, column: usize) -> Self {
        Self { row, column }
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.row + 1, self.column + 1)
    }
}

/// A byte range enriched with the row/column positions of its endpoints.
///
/// The byte range stays authoritative; the points exist for diagnostics only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceSpan {
    /// Authoritative byte range.
    pub bytes: ByteSpan,
    /// Position of the first byte.
    pub start: Point,
    /// Position one past the last byte.
    pub end: Point,
}

impl SourceSpan {
    /// Creates a source span from a byte range and its endpoint positions.
    pub const fn new(bytes: ByteSpan, start: Point, end: Point) -> Self {
        Self { bytes, start, end }
    }
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{} ({})", self.start, self.end, self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteSpan, Point, SourceSpan};

    #[test]
    fn overlap_is_symmetric_and_ignores_empty_spans() {
        let a = ByteSpan::new(0, 10);
        let b = ByteSpan::new(5, 15);
        let insertion = ByteSpan::empty_at(5);

        assert!(a.overlaps(b));
        assert!(b.overlaps(a));
        assert!(!a.overlaps(insertion));
        assert!(!insertion.overlaps(a));
    }

    #[test]
    fn spans_sort_by_start_then_end() {
        let mut spans = vec![ByteSpan::new(10, 12), ByteSpan::new(0, 5), ByteSpan::new(0, 2)];
        spans.sort_unstable();
        assert_eq!(spans, vec![ByteSpan::new(0, 2), ByteSpan::new(0, 5), ByteSpan::new(10, 12)]);
    }

    #[test]
    fn display_is_one_based_for_humans() {
        let span = SourceSpan::new(ByteSpan::new(4, 9), Point::new(0, 4), Point::new(0, 9));
        assert_eq!(span.to_string(), "1:5-1:10 (4..9)");
    }
}
