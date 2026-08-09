//! `hardener exception`: author a policy exception from the finding that needs
//! one.
//!
//! The exception itself is not new. Every plugin has honoured
//! [`PolicyException`] at apply for as long as one could be written, and a
//! declined one has reported itself since the exception-not-applied work. What
//! was missing is a way to write one without hand-editing a root-owned file
//! whose check ids nothing in the interface names.

pub mod document;
