use std::fmt::{Debug, Display, Formatter};
use std::io;

use thiserror::Error;

use yara_x_macros::Error as DeriveError;
use yara_x_parser::ast::Span;
use yara_x_parser::report::ReportBuilder;
use yara_x_parser::report::ReportType;
use yara_x_parser::Error as ParseError;

/// Errors returned while serializing/deserializing compiled rules.
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("not a YARA-X compiled rules file")]
    InvalidFormat,

    #[error("invalid YARA-X compiled rules file")]
    InvalidEncoding(#[from] bincode::Error),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// Error returned by [`crate::Compiler::emit_wasm_file`].
#[derive(Error, Debug)]
#[error(transparent)]
#[doc(hidden)]
pub struct EmitWasmError(#[from] anyhow::Error);

/// Errors returned by the compiler.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error(transparent)]
    CompileError(#[from] CompileError),
}

/// Error produced while compiling rules.
pub struct CompileError(Box<CompileErrorInfo>);

impl CompileError {
    /// Returns additional information about the error.
    pub fn info(&self) -> &CompileErrorInfo {
        self.0.as_ref()
    }
}

impl Debug for CompileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for CompileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<CompileErrorInfo> for CompileError {
    fn from(value: CompileErrorInfo) -> Self {
        Self(Box::new(value))
    }
}

impl std::error::Error for CompileError {}

/// An error occurred during the compilation process.
#[derive(DeriveError)]
#[non_exhaustive]
pub enum CompileErrorInfo {
    #[error("wrong type")]
    #[label(
        "expression should be {expected_types}, but is `{actual_type}`",
        expression_span
    )]
    WrongType {
        detailed_report: String,
        expected_types: String,
        actual_type: String,
        expression_span: Span,
    },

    #[error("mismatching types")]
    #[label("this expression is `{type1}`", type1_span)]
    #[label("this expression is `{type2}`", type2_span)]
    MismatchingTypes {
        detailed_report: String,
        type1: String,
        type2: String,
        type1_span: Span,
        type2_span: Span,
    },

    #[error("wrong arguments")]
    #[label("wrong arguments in this call", args_span)]
    #[note(note)]
    WrongArguments {
        detailed_report: String,
        args_span: Span,
        note: Option<String>,
    },

    #[error("assignment mismatch")]
    #[label("this expects {expected_values} value(s)", error_span)]
    #[label("this produces {actual_values} value(s)", iterable_span)]
    AssignmentMismatch {
        detailed_report: String,
        expected_values: u8,
        actual_values: u8,
        iterable_span: Span,
        error_span: Span,
    },

    #[error("unexpected negative number")]
    #[label("this number can not be negative", span)]
    UnexpectedNegativeNumber { detailed_report: String, span: Span },

    #[error("number out of range")]
    #[label("this number is out of the allowed range [{min}-{max}]", span)]
    NumberOutOfRange {
        detailed_report: String,
        min: i64,
        max: i64,
        span: Span,
    },

    #[error("unknown identifier `{identifier}`")]
    #[label("this identifier has not been declared", span)]
    #[note(note)]
    UnknownIdentifier {
        detailed_report: String,
        identifier: String,
        span: Span,
        note: Option<String>,
    },

    #[error("unknown module `{identifier}`")]
    #[label("module `{identifier}` not found", span)]
    UnknownModule { detailed_report: String, identifier: String, span: Span },

    #[error("invalid range")]
    #[label("higher bound must be greater or equal than lower bound", span)]
    InvalidRange { detailed_report: String, span: Span },

    #[error("duplicate rule `{new_rule}`")]
    #[label(
        "`{new_rule}` declared here for the first time",
        existing_rule_span,
        style = "note"
    )]
    #[label("duplicate declaration of `{new_rule}`", new_rule_span)]
    DuplicateRule {
        detailed_report: String,
        new_rule: String,
        new_rule_span: Span,
        existing_rule_span: Span,
    },

    #[error("rule `{ident}` conflicts with an existing identifier")]
    #[label(
        "identifier already in use by a module or global variable",
        ident_span
    )]
    ConflictingRuleIdentifier {
        detailed_report: String,
        ident: String,
        ident_span: Span,
    },

    #[error("global rule `{global_rule}` depends on non-global rule `{non_global_rule}`")]
    #[label(
        "`{non_global_rule}` is used in the condition of `{global_rule}`",
        non_global_rule_usage_span
    )]
    #[label(
        "non-global rule `{non_global_rule}` declared here",
        non_global_rule_span,
        style = "note"
    )]
    #[label(
        "global rule `{global_rule}` declared here",
        global_rule_span,
        style = "note"
    )]
    WrongRuleDependency {
        detailed_report: String,
        global_rule: String,
        non_global_rule: String,
        global_rule_span: Span,
        non_global_rule_span: Span,
        non_global_rule_usage_span: Span,
    },

    #[error("invalid regular expression")]
    #[label("{error}", span)]
    InvalidRegexp { detailed_report: String, error: String, span: Span },

    #[error("mixing greedy and non-greedy quantifiers in regular expression")]
    #[label("this is {quantifier1_greediness}", quantifier1_span)]
    #[label("this is {quantifier2_greediness}", quantifier2_span)]
    MixedGreediness {
        detailed_report: String,
        quantifier1_greediness: String,
        quantifier2_greediness: String,
        quantifier1_span: Span,
        quantifier2_span: Span,
    },

    #[error("no matching patterns")]
    #[label("there's no pattern in this set", span)]
    #[note(note)]
    EmptyPatternSet {
        detailed_report: String,
        span: Span,
        note: Option<String>,
    },
}
