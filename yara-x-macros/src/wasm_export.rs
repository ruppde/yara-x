extern crate proc_macro;

use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use std::borrow::Cow;
use std::collections::vec_deque::VecDeque;
use std::ops::Add;
use syn::visit::Visit;
use syn::{
    AttributeArgs, GenericArgument, Ident, ItemFn, PatType, PathArguments,
    ReturnType, Type, TypePath,
};

/// Parses signature of a Rust function and returns its mangled named.
struct FuncSignatureParser<'ast> {
    arg_types: Option<VecDeque<&'ast Type>>,
}

impl<'ast> FuncSignatureParser<'ast> {
    fn new() -> Self {
        Self { arg_types: None }
    }

    #[inline(always)]
    fn type_ident(type_path: &TypePath) -> &Ident {
        &type_path.path.segments.last().unwrap().ident
    }

    fn type_path_to_mangled_named(
        type_path: &TypePath,
    ) -> syn::Result<Cow<'static, str>> {
        match Self::type_ident(type_path).to_string().as_str() {
            "i32" | "i64" => Ok(Cow::Borrowed("i")),
            "f32" | "f64" => Ok(Cow::Borrowed("f")),
            "bool" => Ok(Cow::Borrowed("b")),
            "PatternId" | "RuleId" => Ok(Cow::Borrowed("i")),
            "RegexpId" => Ok(Cow::Borrowed("r")),
            "RuntimeString" => Ok(Cow::Borrowed("s")),
            type_ident => Err(syn::Error::new_spanned(
                type_path,
                format!(
                    "type `{}` is not supported as argument or return type",
                    type_ident
                ),
            )),
        }
    }

    fn mangled_type(ty: &Type) -> syn::Result<Cow<'static, str>> {
        match ty {
            Type::Path(type_path) => {
                if Self::type_ident(type_path) == "Option" {
                    if let PathArguments::AngleBracketed(angle_bracketed) =
                        &type_path.path.segments.last().unwrap().arguments
                    {
                        if let GenericArgument::Type(ty) =
                            angle_bracketed.args.first().unwrap()
                        {
                            Ok(Self::mangled_type(ty)?.add("u"))
                        } else {
                            unreachable!()
                        }
                    } else {
                        unreachable!()
                    }
                } else {
                    Self::type_path_to_mangled_named(type_path)
                }
            }
            Type::Group(group) => Self::mangled_type(group.elem.as_ref()),
            Type::Tuple(tuple) => {
                let mut result = String::new();
                for elem in tuple.elems.iter() {
                    result.push_str(Self::mangled_type(elem)?.as_ref());
                }
                Ok(Cow::Owned(result))
            }
            _ => Err(syn::Error::new_spanned(ty, "unsupported type")),
        }
    }

    fn mangled_return_type(ty: &ReturnType) -> syn::Result<Cow<'static, str>> {
        match ty {
            // The function doesn't return anything.
            ReturnType::Default => Ok(Cow::Borrowed("")),
            // The function returns some type.
            ReturnType::Type(_, ty) => Self::mangled_type(ty),
        }
    }

    fn parse(&mut self, func: &'ast syn::ItemFn) -> syn::Result<String> {
        self.arg_types = Some(VecDeque::new());

        // This loop traverses the function arguments' AST, populating
        // `self.arg_types`.
        for fn_arg in func.sig.inputs.iter() {
            self.visit_fn_arg(fn_arg);
        }

        let mut arg_types = self.arg_types.take().unwrap();

        // Make sure that the first argument is `Caller`.
        let first_argument_is_ok =
            if let Some(Type::Path(type_path)) = arg_types.pop_front() {
                Self::type_ident(type_path) == "Caller"
            } else {
                false
            };

        if !first_argument_is_ok {
            return Err(syn::Error::new_spanned(
                &func.sig,
                format!(
                    "the first argument for function `{}` must be `Caller<'_, ScanContext>`",
                    func.sig.ident),
            ));
        }

        let mut mangled_name = String::from("@");

        for arg_type in arg_types {
            mangled_name.push_str(Self::mangled_type(arg_type)?.as_ref());
        }

        mangled_name.push('@');
        mangled_name.push_str(&Self::mangled_return_type(&func.sig.output)?);

        Ok(mangled_name)
    }
}

impl<'ast> Visit<'ast> for FuncSignatureParser<'ast> {
    fn visit_pat_type(&mut self, pat_type: &'ast PatType) {
        self.arg_types.as_mut().unwrap().push_back(pat_type.ty.as_ref());
    }
}

#[derive(Debug, FromMeta)]
/// Arguments received by the `#[wasm_export]` macro.
pub struct WasmExportArgs {
    name: Option<String>,
    #[darling(default)]
    public: bool,
}

/// Implementation for the `#[wasm_export]` attribute macro.
///
/// This attribute is used in functions that will be called from WASM.
/// For each function using this attribute the macro adds an entry to the
/// `WASM_EXPORTS` global slice. This is done by adding a code snippet
/// similar to the one shown below.
///
/// # Example
///
/// Suppose that our function is:
///
/// ```text
/// #[wasm_export]
/// fn add(caller: Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {   
///     a + b
/// }
/// ```
///
/// The code generated will be:
///
/// ```text
/// #[distributed_slice(WASM_EXPORTS)]
/// pub(crate) static export__add: WasmExport = WasmExport {
///     name: "add",
///     mangled_name: "add@ii@i",
///     rust_module_path: "yara_x::modules::my_module",
///     func: &WasmExportedFn2 { target_fn: &add },
/// };
/// ```
///
/// Notice that the generated code uses `WasmExportedFn2` because the function
/// receives two parameters (not counting `caller: Caller<'_, ScanContext>`)
///
pub(crate) fn impl_wasm_export_macro(
    attr_args: AttributeArgs,
    func: ItemFn,
) -> syn::Result<TokenStream> {
    let attr_args = WasmExportArgs::from_list(&attr_args)?;

    let fn_name = &func.sig.ident;
    let fn_name_str = if let Some(name) = attr_args.name {
        name
    } else {
        fn_name.to_string()
    };

    if func.sig.inputs.is_empty() {
        return Err(syn::Error::new_spanned(
            &func.sig,
            format!(
                "function `{}` must have at least one argument of type `Caller<'_, ScanContext>`", 
                fn_name),
        ));
    }

    let num_args = func.sig.inputs.len() - 1;

    let export_ident = format_ident!("export__{}", fn_name);
    let exported_fn_ident = format_ident!("WasmExportedFn{}", num_args);
    let public = attr_args.public;

    let mut func_sig_parser = FuncSignatureParser::new();

    let mangled_fn_name =
        format!("{}{}", fn_name_str, func_sig_parser.parse(&func)?);

    let fn_descriptor = quote! {
        #[allow(non_upper_case_globals)]
        #[distributed_slice(WASM_EXPORTS)]
        pub(crate) static #export_ident: WasmExport = WasmExport {
            name: #fn_name_str,
            mangled_name: #mangled_fn_name,
            public: #public,
            rust_module_path: module_path!(),
            func: &#exported_fn_ident { target_fn: &#fn_name },
        };
    };

    let mut token_stream = func.to_token_stream();
    token_stream.extend(fn_descriptor);

    Ok(token_stream)
}

#[cfg(test)]
mod tests {
    use crate::wasm_export::FuncSignatureParser;
    use syn::parse_quote;

    #[test]
    fn func_signature_parser() {
        let mut parser = FuncSignatureParser::new();

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> i32 { 0 }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@i");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> (i32, i32) { (0,0) }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@ii");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>, a: i32, b: i32) -> i32 { a + b }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@ii@i");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> Option<()> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@u");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> Option<i64> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@iu");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> Option<i64> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@iu");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> Option<(i64, f64)> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@ifu");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>)  {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>) -> (i64, RuntimeString) {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@is");
    }
}
