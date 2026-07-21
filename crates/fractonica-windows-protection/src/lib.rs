//! Safe, byte-oriented access to the current-user Windows DPAPI scope.

#![deny(unsafe_op_in_unsafe_fn)]

use std::io;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

/// Encrypts bytes for the current Windows user without displaying UI.
pub fn protect(data: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    transform(data, entropy, true)
}

/// Decrypts bytes for the current Windows user without displaying UI.
pub fn unprotect(data: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    transform(data, entropy, false)
}

#[cfg(windows)]
fn transform(data: &[u8], entropy: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    // DATA_BLOB exposes mutable pointers even for logical inputs. Keep private
    // owned copies so the FFI never receives pointers into immutable storage.
    let mut input_bytes = data.to_vec();
    let mut entropy_bytes = entropy.to_vec();
    let input = blob(&mut input_bytes)?;
    let entropy = blob(&mut entropy_bytes)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input slices outlive the call. The API initializes `output` with
    // a LocalAlloc allocation on success, which is copied and freed below.
    let succeeded = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful API call returned `cbData` initialized bytes.
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }
        .to_vec();
    // SAFETY: DPAPI documents LocalFree as the matching deallocator.
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(result)
}

#[cfg(windows)]
fn blob(bytes: &mut [u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DPAPI input is too large"))?,
        pbData: bytes.as_mut_ptr(),
    })
}

#[cfg(not(windows))]
fn transform(_data: &[u8], _entropy: &[u8], _encrypt: bool) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows DPAPI is only available on Windows",
    ))
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn current_user_round_trip_with_entropy() {
        let plaintext = [42_u8; 32];
        let entropy = b"fractonica/test/v1";
        let protected = super::protect(&plaintext, entropy).unwrap();
        assert_ne!(protected, plaintext);
        assert_eq!(super::unprotect(&protected, entropy).unwrap(), plaintext);
        assert!(super::unprotect(&protected, b"wrong entropy").is_err());
    }
}
