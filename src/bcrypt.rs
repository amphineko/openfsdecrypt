use std::io::{BufReader, BufWriter, Read, Write};
use windows_sys::w;
use windows_sys::Win32::Foundation::{
    STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_NO_MEMORY, STATUS_SUCCESS,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptGenerateSymmetricKey, BCryptGetProperty, BCryptOpenAlgorithmProvider,
    BCryptSetProperty, BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_CHAINING_MODE,
    BCRYPT_OBJECT_LENGTH,
};

use crate::progress;

fn format_message(status: i32) -> String {
    return match status {
        STATUS_INVALID_PARAMETER => "STATUS_INVALID_PARAMETER".to_string(),
        STATUS_NO_MEMORY => "STATUS_NO_MEMORY".to_string(),
        STATUS_NOT_FOUND => "STATUS_NOT_FOUND".to_string(),
        STATUS_SUCCESS => "STATUS_SUCCESS".to_string(),
        _ => "Unknown error code".to_string(),
    };
}

macro_rules! check_ntstatus {
    ($status:expr, $func:ident) => {
        if $status != STATUS_SUCCESS {
            let error = format_message($status);
            panic!(
                "{} failed with {} (0x{:x})",
                stringify!($func),
                error,
                $status
            );
        }
    };
}

pub unsafe fn decrypt_bcrypt<W: std::io::Write>(
    key: [u8; 16],
    input_iv: [u8; 16],
    input: &mut BufReader<&std::fs::File>,
    length: u64,
    output: &mut BufWriter<W>,
) {
    let mut alg_handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();

    check_ntstatus!(
        BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_AES_ALGORITHM,
            std::ptr::null_mut(),
            0
        ),
        BCryptOpenAlgorithmProvider
    );

    check_ntstatus!(
        BCryptSetProperty(
            alg_handle,
            BCRYPT_CHAINING_MODE,
            w!("ChainingModeCBC") as *const u8,
            2 * "ChainingModeCBC".len() as u32,
            0
        ),
        BCryptSetProperty
    );

    let mut object_size: u32 = 0;
    check_ntstatus!(
        BCryptGetProperty(
            alg_handle,
            BCRYPT_OBJECT_LENGTH,
            &mut object_size as *mut u32 as *mut u8,
            std::mem::size_of::<u32>() as u32,
            &mut [0 as u32; 1] as *mut u32,
            0
        ),
        BCryptGetProperty
    );

    let mut key_handle = std::ptr::null_mut();
    let mut key_object = vec![0; object_size as usize];

    check_ntstatus!(
        BCryptGenerateSymmetricKey(
            alg_handle,
            &mut key_handle,
            key_object.as_mut_ptr(),
            object_size,
            key.as_ptr(),
            key.len() as u32,
            0,
        ),
        BCryptGenerateSymmetricKey
    );

    let mut offset: u64 = 0;
    let mut read_buffer = vec![0; 0x1000];
    let mut decrypt_buffer = vec![0; 0x1000];
    let progress = progress::new_decrypt_progress_bar(length);
    while let Ok(bytes_read) = input.read(&mut read_buffer) {
        if bytes_read == 0 {
            break;
        }
        assert!(bytes_read == 0x1000);

        let iv = (0..16)
            .map(|i| offset.overflowing_shr(8 * (i & 7)).0 as u8 ^ input_iv[i as usize])
            .collect::<Vec<u8>>();

        let mut bytes_decrypted = 0;
        check_ntstatus!(
            BCryptDecrypt(
                key_handle,
                read_buffer.as_ptr(),
                bytes_read as u32,
                std::ptr::null_mut(),
                iv.as_ptr() as *mut u8,
                iv.len() as u32,
                decrypt_buffer.as_mut_ptr(),
                decrypt_buffer.len() as u32,
                &mut bytes_decrypted,
                0
            ),
            BCryptDecrypt
        );
        assert!(bytes_decrypted == bytes_read as u32);

        output
            .write(&decrypt_buffer[..bytes_decrypted as usize])
            .expect("Cannot write to output");
        let _ = output.flush();

        offset += bytes_decrypted as u64;
        assert!(offset % 0x1000 == 0);
        if offset >= length {
            break;
        }

        progress.inc(bytes_read as u64);
    }
    progress.finish();
}
