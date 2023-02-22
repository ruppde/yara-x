use std::ffi::{c_char, CStr};

#[repr(C)]
pub enum YRX_ERROR {
    SUCCESS,
    FOO,
}

pub struct YRX_RULES {
    #[allow(dead_code)]
    r: yara_x::Rules,
}

/// Compile YARA source code and return the rules in compiled form.
///
/// The caller is responsible for destroying the YR_RULES object by calling
/// [`yrx_rules_destroy`].
#[no_mangle]
pub extern "C" fn yrx_compile(
    src: *const c_char,
    rules: &mut *mut YRX_RULES,
) -> YRX_ERROR {
    let c_str = unsafe { CStr::from_ptr(src) };

    let compiled_rules =
        match std::panic::catch_unwind(|| yara_x::compile(c_str.to_bytes())) {
            Ok(rules) => rules,
            Err(err) => {
                // Capture panics and return an error to the caller. Panics
                // should not propagate through a FFI boundary.
                todo!()
            }
        };

    match compiled_rules {
        Ok(r) => {
            *rules = Box::into_raw(Box::new(YRX_RULES { r }));
        }
        Err(err) => {
            todo!()
        }
    }

    YRX_ERROR::SUCCESS
}

/// Destroys a [`YRX_RULES`] object.
#[no_mangle]
pub extern "C" fn yrx_rules_destroy(rules: *mut YRX_RULES) {
    unsafe { drop(Box::from_raw(rules)) };
}
