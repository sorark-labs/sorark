//! AST visitor that inspects a single function body for storage calls, TTL extensions,
//! `require_auth` guards, `update_current_contract_wasm` invocations, loop nesting,
//! and Soroban `Symbol` string literals.

use super::const_eval::{eval_u64_expr, expr_to_compact_string, pat_to_ident_string};
use super::context::{
    ParsedFunction, StorageOp, StorageOpKind, SymbolLiteralCall, WasmUpgradeCall,
};
use super::types::syn_type_to_typeref;
use proc_macro2::Span;
use sorark_ir::{StorageTier, TypeRef};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprForLoop, ExprLit, ExprLoop, ExprMacro, ExprMethodCall, ExprPath, ExprWhile,
    FnArg, Lit, Local, Pat, Stmt,
};

/// Intra-function AST visitor that tracks local variable types, storage operations,
/// loop depth, symbol literals, authorization checks, and helper calls.
pub(super) struct FnBodyAnalyzer<'a> {
    source_lines: &'a [&'a str],
    constants: &'a HashMap<String, u64>,
    local_var_types: HashMap<String, TypeRef>,
    storage_ops: Vec<StorageOp>,
    symbol_literals: Vec<SymbolLiteralCall>,
    loop_depth: usize,
    has_require_auth: bool,
    wasm_upgrade_calls: Vec<WasmUpgradeCall>,
    called_functions: Vec<String>,
}

impl<'a> FnBodyAnalyzer<'a> {
    /// Creates a new body analyzer for a function within a file whose lines and constants are known.
    pub(super) fn new(source_lines: &'a [&'a str], constants: &'a HashMap<String, u64>) -> Self {
        Self {
            source_lines,
            constants,
            local_var_types: HashMap::new(),
            storage_ops: Vec::new(),
            symbol_literals: Vec::new(),
            loop_depth: 0,
            has_require_auth: false,
            wasm_upgrade_calls: Vec::new(),
            called_functions: Vec::new(),
        }
    }

    /// Seeds `local_var_types` with the declared parameter types of the function signature.
    pub(super) fn seed_fn_inputs(
        &mut self,
        inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>,
    ) {
        for arg in inputs {
            if let FnArg::Typed(pat_ty) = arg
                && let Some(ident) = pat_to_ident_string(&pat_ty.pat)
            {
                self.local_var_types
                    .insert(ident, syn_type_to_typeref(&pat_ty.ty));
            }
        }
    }

    /// Converts the accumulated visitor state into a [`ParsedFunction`].
    pub(super) fn into_parsed_function(
        self,
        name: String,
        is_contract_entrypoint: bool,
        is_pub: bool,
        file: &str,
        line: usize,
        column: usize,
    ) -> ParsedFunction {
        ParsedFunction {
            name,
            is_contract_entrypoint,
            is_pub,
            file: file.to_string(),
            line,
            column,
            storage_ops: self.storage_ops,
            symbol_literals: self.symbol_literals,
            has_direct_require_auth: self.has_require_auth,
            wasm_upgrade_calls: self.wasm_upgrade_calls,
            called_functions: self.called_functions,
        }
    }

    /// Extracts `(1_based_line, 1_based_col, trimmed_source_line)` for a `proc_macro2::Span`.
    fn line_snippet(&self, span: Span) -> (usize, usize, String) {
        let start = span.start();
        let line = start.line.max(1);
        let col = start.column + 1;
        let snippet = self
            .source_lines
            .get(line - 1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        (line, col, snippet)
    }

    /// Records the type of a local `let` binding from either its explicit type annotation
    /// or its initializer expression.
    fn record_local_binding(&mut self, local: &Local) {
        match &local.pat {
            Pat::Type(pat_ty) => {
                if let Some(var_name) = pat_to_ident_string(&pat_ty.pat) {
                    self.local_var_types
                        .insert(var_name, syn_type_to_typeref(&pat_ty.ty));
                }
            }
            Pat::Ident(pat_ident) => {
                if let Some(init) = &local.init
                    && let Some(inferred) = self.infer_expr_type(&init.expr)
                {
                    self.local_var_types
                        .insert(pat_ident.ident.to_string(), inferred);
                }
            }
            _ => {}
        }
    }

    /// Infers the [`TypeRef`] of a value expression passed to `storage().set(&key, &val)`.
    fn infer_expr_type(&self, expr: &Expr) -> Option<TypeRef> {
        match expr {
            Expr::Reference(r) => self.infer_expr_type(&r.expr),
            Expr::Paren(p) => self.infer_expr_type(&p.expr),
            Expr::Path(ep) if ep.path.segments.len() == 1 => {
                let var_name = ep.path.segments[0].ident.to_string();
                self.local_var_types.get(&var_name).cloned()
            }
            Expr::Struct(es) => es
                .path
                .segments
                .last()
                .map(|seg| TypeRef::Custom(seg.ident.to_string())),
            Expr::Call(call) => infer_constructor_call_type(call),
            Expr::MethodCall(mc) if mc.method == "clone" => self.infer_expr_type(&mc.receiver),
            Expr::Macro(mac) => infer_soroban_macro_type(mac),
            _ => None,
        }
    }

    /// Records a storage method call (`set`, `update`, `extend_ttl`, `get`, `remove`, `has`).
    fn record_storage_method_call(
        &mut self,
        node: &ExprMethodCall,
        tier: StorageTier,
        kind: StorageOpKind,
    ) {
        let (line, column, snippet) = self.line_snippet(node.method.span());
        let key_expr = node.args.first().map(expr_to_compact_string);
        let value_expr = node.args.get(1).map(expr_to_compact_string);
        let inferred_value_type = node.args.get(1).and_then(|arg| self.infer_expr_type(arg));
        let ttl_bounds = if kind == StorageOpKind::ExtendTtl {
            Some(self.extract_ttl_bounds(node, tier))
        } else {
            None
        };

        self.storage_ops.push(StorageOp {
            tier,
            kind,
            key_expr,
            value_expr,
            inferred_value_type,
            ttl_bounds,
            in_loop: self.loop_depth > 0,
            line,
            column,
            snippet,
        });
    }

    /// Evaluates `(threshold, extend_to)` arguments on an `extend_ttl` invocation.
    fn extract_ttl_bounds(
        &self,
        node: &ExprMethodCall,
        tier: StorageTier,
    ) -> (Option<u64>, Option<u64>) {
        let (thresh_idx, extend_idx) = match tier {
            StorageTier::Instance => (0, 1),
            StorageTier::Persistent | StorageTier::Temporary => (1, 2),
        };
        let threshold = node
            .args
            .get(thresh_idx)
            .and_then(|e| eval_u64_expr(e, self.constants));
        let extend_to = node
            .args
            .get(extend_idx)
            .and_then(|e| eval_u64_expr(e, self.constants));
        (threshold, extend_to)
    }

    /// Records `symbol_short!("...")` macro calls for static length/charset validation (`ARK-STOR-007`).
    fn check_symbol_short_macro(&mut self, node: &ExprMacro) {
        let Some(last) = node.mac.path.segments.last() else {
            return;
        };
        if last.ident != "symbol_short" {
            return;
        }
        if let Ok(Lit::Str(lit_str)) = syn::parse2::<Lit>(node.mac.tokens.clone()) {
            let (line, column, snippet) = self.line_snippet(last.ident.span());
            self.symbol_literals.push(SymbolLiteralCall {
                is_short: true,
                value: lit_str.value(),
                line,
                column,
                snippet,
            });
        }
    }

    /// Records `Symbol::new(&env, "...")` function calls for static length/charset validation (`ARK-STOR-007`).
    fn check_symbol_new_call(&mut self, node: &ExprCall) {
        let Expr::Path(ExprPath { path, .. }) = &*node.func else {
            return;
        };
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segs.len() >= 2
            && segs[segs.len() - 2] == "Symbol"
            && segs[segs.len() - 1] == "new"
            && let Some(Expr::Lit(ExprLit {
                lit: Lit::Str(lit_str),
                ..
            })) = node.args.get(1)
        {
            let (line, column, snippet) = self.line_snippet(path.span());
            self.symbol_literals.push(SymbolLiteralCall {
                is_short: false,
                value: lit_str.value(),
                line,
                column,
                snippet,
            });
        }
    }
}

impl<'ast> Visit<'ast> for FnBodyAnalyzer<'_> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Local(local) = stmt {
            self.record_local_binding(local);
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        visit::visit_expr(self, &node.expr);
        self.loop_depth += 1;
        visit::visit_block(self, &node.body);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.loop_depth += 1;
        visit::visit_expr_while(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast ExprLoop) {
        self.loop_depth += 1;
        visit::visit_expr_loop(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        self.check_symbol_short_macro(node);
        visit::visit_expr_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        // Visit receiver and arguments first so statement execution order is preserved.
        visit::visit_expr_method_call(self, node);

        let method_name = node.method.to_string();

        if method_name == "require_auth" || method_name == "require_auth_for_args" {
            self.has_require_auth = true;
            return;
        }

        if method_name == "update_current_contract_wasm" {
            let (line, column, snippet) = self.line_snippet(node.method.span());
            self.wasm_upgrade_calls.push(WasmUpgradeCall {
                line,
                column,
                snippet,
                auth_seen_before_call: self.has_require_auth,
            });
            return;
        }

        if let Some(tier) = detect_storage_tier_on_receiver(&node.receiver) {
            if let Some(kind) = StorageOpKind::from_method_name(&method_name) {
                self.record_storage_method_call(node, tier, kind);
            }
        } else {
            self.called_functions.push(method_name);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        visit::visit_expr_call(self, node);
        self.check_symbol_new_call(node);
        if let Expr::Path(ExprPath { path, .. }) = &*node.func
            && let Some(last) = path.segments.last()
        {
            self.called_functions.push(last.ident.to_string());
        }
    }
}

/// Walks chained receiver calls (`env.storage().instance()`) to identify the [`StorageTier`].
fn detect_storage_tier_on_receiver(receiver: &Expr) -> Option<StorageTier> {
    let Expr::MethodCall(mc) = receiver else {
        return None;
    };
    StorageTier::from_accessor(&mc.method.to_string())
        .or_else(|| detect_storage_tier_on_receiver(&mc.receiver))
}

/// Infers collection/buffer types from constructor calls such as `Map::new(&env)` or `Vec::new(&env)`.
fn infer_constructor_call_type(call: &ExprCall) -> Option<TypeRef> {
    let Expr::Path(ExprPath { path, .. }) = &*call.func else {
        return None;
    };
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    if segs.len() < 2 {
        return None;
    }
    match segs[segs.len() - 2].as_str() {
        "Map" => Some(TypeRef::Map {
            key: Box::new(TypeRef::Val),
            value: Box::new(TypeRef::Val),
        }),
        "Vec" => Some(TypeRef::Vec(Box::new(TypeRef::Val))),
        "Bytes" => Some(TypeRef::Bytes),
        "String" => Some(TypeRef::String),
        _ => None,
    }
}

/// Infers collection types constructed via Soroban macros (`vec![&env, ...]`, `map![&env, ...]`).
fn infer_soroban_macro_type(mac: &syn::ExprMacro) -> Option<TypeRef> {
    let name = mac.mac.path.segments.last()?.ident.to_string();
    match name.as_str() {
        "vec" => Some(TypeRef::Vec(Box::new(TypeRef::Val))),
        "map" => Some(TypeRef::Map {
            key: Box::new(TypeRef::Val),
            value: Box::new(TypeRef::Val),
        }),
        "bytes" => Some(TypeRef::Bytes),
        _ => None,
    }
}
