//! Runs one command buffer through libnftables, in process.
//!
//! This is the only crate in the workspace that contains `unsafe`. It exists
//! so the daemon can load a ruleset without starting a process or building a
//! command line. Every `unsafe` block below has an audit note.
//!
//! libnftables applies a buffer as one netlink transaction: either every
//! command in it takes effect or none does.

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint},
    fmt,
};

/// Opaque `struct nft_ctx` from `<nftables/libnftables.h>`.
#[repr(C)]
struct NftCtx {
    _opaque: [u8; 0],
}

/// `NFT_CTX_DEFAULT` from libnftables.h.
const NFT_CTX_DEFAULT: u32 = 0;
/// `NFT_CTX_OUTPUT_JSON` from libnftables.h: parse input and print output as JSON.
const NFT_CTX_OUTPUT_JSON: c_uint = 1 << 4;

// AUDIT: signatures copied from nftables 1.1.6 include/nftables/libnftables.h.
// All eight functions have been part of libnftables.so.1 since nftables 0.9.0.
unsafe extern "C" {
    fn nft_ctx_new(flags: u32) -> *mut NftCtx;
    fn nft_ctx_free(ctx: *mut NftCtx);
    fn nft_ctx_output_set_flags(ctx: *mut NftCtx, flags: c_uint);
    fn nft_ctx_buffer_output(ctx: *mut NftCtx) -> c_int;
    fn nft_ctx_buffer_error(ctx: *mut NftCtx) -> c_int;
    fn nft_ctx_get_output_buffer(ctx: *mut NftCtx) -> *const c_char;
    fn nft_ctx_get_error_buffer(ctx: *mut NftCtx) -> *const c_char;
    fn nft_run_cmd_from_buffer(ctx: *mut NftCtx, buf: *const c_char) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftError {
    /// libnftables could not create a context.
    NoContext,
    /// The command buffer contained a NUL byte.
    NulInCommand,
    /// nftables refused the buffer. Nothing in it was applied.
    Refused(String),
}

impl fmt::Display for NftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NftError::NoContext => f.write_str("libnftables could not create a context"),
            NftError::NulInCommand => f.write_str("the nftables command contains a NUL byte"),
            NftError::Refused(msg) => write!(f, "nftables refused the ruleset: {}", msg.trim()),
        }
    }
}

impl std::error::Error for NftError {}

/// Owns one `nft_ctx` and frees it on drop, including on early return.
struct Ctx(*mut NftCtx);

impl Drop for Ctx {
    fn drop(&mut self) {
        // AUDIT: `self.0` came from `nft_ctx_new`, was checked non-null in
        // `run_json`, and is freed exactly once, here.
        unsafe { nft_ctx_free(self.0) }
    }
}

/// Copies a C string owned by the context into a `String`.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string that stays valid
/// for the duration of the call.
unsafe fn copy(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // AUDIT: non-null was checked above; the caller guarantees NUL termination.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Runs a libnftables JSON document and returns what nftables printed.
///
/// The document is one transaction. On `Err`, the kernel ruleset is unchanged.
pub fn run_json(json: &str) -> Result<String, NftError> {
    let buf = CString::new(json).map_err(|_| NftError::NulInCommand)?;

    // AUDIT: `nft_ctx_new` takes a flags word and returns an owned context or
    // null. Null is handled on the next line.
    let raw = unsafe { nft_ctx_new(NFT_CTX_DEFAULT) };
    if raw.is_null() {
        return Err(NftError::NoContext);
    }
    let ctx = Ctx(raw);

    // AUDIT: `ctx.0` is a live context for the whole block. `buf` is a valid
    // NUL-terminated string that outlives the call. Output and errors are
    // buffered inside the context instead of going to stdout and stderr, and
    // the two getters return pointers owned by the context, which is still
    // alive when `copy` reads them.
    unsafe {
        nft_ctx_output_set_flags(ctx.0, NFT_CTX_OUTPUT_JSON);
        if nft_ctx_buffer_output(ctx.0) != 0 || nft_ctx_buffer_error(ctx.0) != 0 {
            return Err(NftError::NoContext);
        }
        let rc = nft_run_cmd_from_buffer(ctx.0, buf.as_ptr());
        let output = copy(nft_ctx_get_output_buffer(ctx.0));
        let error = copy(nft_ctx_get_error_buffer(ctx.0));
        if rc == 0 {
            Ok(output)
        } else {
            Err(NftError::Refused(error))
        }
    }
}
