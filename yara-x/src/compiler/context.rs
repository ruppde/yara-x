use std::mem::size_of;
use std::rc::Rc;

use yara_x_parser::report::ReportBuilder;
use yara_x_parser::Warning;

use crate::compiler::{ir, IdentId, PatternId, RuleId, RuleInfo};
use crate::string_pool::StringPool;
use crate::symbols::{StackedSymbolTable, SymbolLookup};
use crate::types::Type;
use crate::wasm;

/// Structure that contains information and data structures required during the
/// current compilation process.
pub(in crate::compiler) struct CompileContext<'a, 'src, 'sym> {
    /// Builder for creating error and warning reports.
    pub report_builder: &'a ReportBuilder,

    /// Symbol table that contains the currently defined identifiers, modules,
    /// functions, etc.
    pub symbol_table: &'a mut StackedSymbolTable<'sym>,

    /// Symbol table for the currently active structure. When this contains
    /// some value, symbols are looked up in this table and the main symbol
    /// table (i.e: `symbol_table`) is ignored.
    pub current_struct: Option<Rc<dyn SymbolLookup + 'a>>,

    /// Information about the rules compiled so far.
    pub rules: &'a Vec<RuleInfo>,

    /// A vector that contains the IR for the patterns declared in the current
    /// rule, accompanied by their corresponding [`PatternId`].
    pub current_rule_patterns:
        &'a mut Vec<(PatternId, ir::PatternInRule<'src>)>,

    /// Warnings generated during the compilation.
    pub warnings: &'a mut Vec<Warning>,

    /// Pool with identifiers used in the rules.
    pub ident_pool: &'a mut StringPool<IdentId>,

    /// Stack of variables. These are local variables used during the
    /// evaluation of rule conditions, for example for storing loop variables.
    pub vars: VarStack,
}

impl<'a, 'src, 'sym> CompileContext<'a, 'src, 'sym> {
    /// Returns a [`RuleInfo`] given its [`RuleId`].
    ///
    /// # Panics
    ///
    /// If no rule with such [`RuleId`] exists.
    #[inline]
    pub fn get_rule(&self, rule_id: RuleId) -> &RuleInfo {
        self.rules.get(rule_id.0 as usize).unwrap()
    }

    /// Returns the [`RuleInfo`] structure corresponding to the rule currently
    /// being compiled.
    #[inline]
    pub fn get_current_rule(&self) -> &RuleInfo {
        self.rules.last().unwrap()
    }

    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return its [`PatternID`].
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    ///
    /// # Panics
    ///
    /// Panics if the current rule does not have the requested pattern.
    pub fn get_pattern_id(&self, ident: &str) -> PatternId {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        for (pattern_id, pattern) in self.current_rule_patterns.iter() {
            // Ignore the first character (`$`, `#`, `@` or `!`) while
            // comparing the identifiers.
            if pattern.identifier()[1..] == ident[1..] {
                return *pattern_id;
            }
        }

        panic!("pattern `{}` not found", ident);
    }

    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return a mutable reference the [ir::PatternInRule]
    /// node in the IR.
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    ///
    /// # Panics
    ///
    /// Panics if the current rule does not have the requested pattern.
    pub fn get_pattern_mut(
        &mut self,
        ident: &str,
    ) -> &mut ir::PatternInRule<'src> {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        for (_, pattern) in self.current_rule_patterns.iter_mut() {
            if pattern.identifier()[1..] == ident[1..] {
                return pattern;
            }
        }

        panic!("pattern `{}` not found", ident);
    }
}

/// Represents a stack of variables.
///
/// The variables stack is composed of frames that are stacked one at the
/// top of another. Each frame can contain one or more variables.
///
/// This stack is stored in WASM main memory, in a memory region that goes
/// from [`wasm::VARS_STACK_START`] to [`wasm::VARS_STACK_END`]. The stack
/// is also mirrored at host-side (with host-side we refer to Rust code
/// called from WASM code), because values like structures, maps, and
/// arrays can't be handled by WASM code directly, and they must be
/// accessible to Rust functions called from WASM. These two stacks (the
/// WASM-side stack and the host-side stack) could be fully independent,
/// but they are mirrored for simplicity. This means that calls to this
/// function reserves space in both stacks at the same time, and therefore
/// their sizes are always the same.
///
/// However, each stack slot is used either by WASM-side code or by
/// host-side code, but not by both. The slots that are used by WASM-side
/// remain with empty values in the host-side stack, while the slots that
/// are used by host-side code remain unused and undefined in WASM
/// memory.
pub(crate) struct VarStack {
    pub used: i32,
}

impl VarStack {
    /// Creates a stack of variables.
    pub fn new() -> Self {
        Self { used: 0 }
    }

    /// Creates a new stack frame with the given capacity on top of the
    /// existing ones. The returned stack frame can hold the specified
    /// number of variables, but not more.
    ///
    /// Use [`VarStackFrame::new_var`] of allocating individual variables
    /// within a frame.
    pub fn new_frame(&mut self, capacity: i32) -> VarStackFrame {
        let start = self.used;
        self.used += capacity;

        if self.used * size_of::<i64>() as i32
            > wasm::VARS_STACK_END - wasm::VARS_STACK_START
        {
            panic!("variables stack overflow");
        }

        VarStackFrame { start, capacity, used: 0 }
    }

    /// Unwinds the stack freeing all frames that were allocated after the
    /// given one, the given frame inclusive.
    pub fn unwind(&mut self, frame: &VarStackFrame) {
        if self.used < frame.start {
            panic!("double-free in VarStack")
        }
        self.used = frame.start;
    }
}

/// Represents a frame in the stack of variables.
///
/// Frames are stacked one in top of another, individual variables are
/// allocated within a frame.
#[derive(Clone)]
pub(crate) struct VarStackFrame {
    pub start: i32,
    pub used: i32,
    pub capacity: i32,
}

impl VarStackFrame {
    /// Allocates space for a new variable in the stack.
    ///
    /// # Panics
    ///
    /// Panics if trying to allocate more variables than the frame capacity.
    pub fn new_var(&mut self, ty: Type) -> Var {
        let index = self.used + self.start;
        self.used += 1;
        if self.used > self.capacity {
            panic!("VarStack exceeding its capacity: {}", self.capacity);
        }
        Var { ty, index }
    }
}

/// Represents a variable in the stack.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Var {
    /// The type of the variable
    pub ty: Type,
    /// The index corresponding to this variable. This index is used for
    /// locating the variable's value in WASM memory. The variable resides at
    /// [`wasm::VARS_STACK_START`] + index * sizeof(i64).
    pub index: i32,
}
