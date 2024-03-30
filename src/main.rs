mod bcrypt;
mod progress;

use clap::Parser;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::PathBuf;

const NTFS_HEADER: [u8; 16] = [
    0xEB, 0x52, 0x90, 0x4E, 0x54, 0x46, 0x53, 0x20, 0x20, 0x20, 0x20, 0x00, 0x10, 0x01, 0x00, 0x00,
];

#[derive(Debug, Parser)]
struct Cli {
    #[arg(
        short = 'k',
        help = "Path to the file of AES-128 key, must be 16 bytes"
    )]
    key: String,

    #[arg(short = 'i')]
    input: PathBuf,

    #[arg(short = 'o')]
    output: PathBuf,

    #[arg(short = 's')]
    offset: Option<u64>,

    #[arg(short = 'm', default_value = "wGO/b1YtCE15Y8mH9SgXYQ==")]
    magic: String,
}

fn main() {
    let cli = Cli::parse();
    let offset = cli.offset.unwrap_or(0x200000);

    let raw_key = fs::read(&cli.key).expect("Unable to read key file");
    if raw_key.len() < 16 {
        panic!("Key must be 16 bytes");
    }
    if raw_key.len() > 16 {
        println!("Key is longer than 16 bytes, remaining bytes will be ignored");
    }

    // strip first 16 bytes
    let key: [u8; 16] = raw_key[0..16].try_into().expect("Cannot slice key");

    let file = OpenOptions::new()
        .read(true)
        .open(&cli.input)
        .unwrap_or_else(|error| {
            panic!("Cannot open input file: {}", error);
        });

    let mut reader = BufReader::new(&file);

    let output = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&cli.output)
        .unwrap_or_else(|error| {
            panic!("Cannot open output file: {}", error);
        });
    output.set_len(0).unwrap_or_else(|error| {
        panic!("Cannot truncate output file: {}", error);
    });
    let mut writer = BufWriter::new(&output);

    // phase 1: decrypt with NTFS header as IV, derive IV from the first 16 bytes

    let mut iv = [0; 16];
    reader.seek(SeekFrom::Start(offset)).expect("Cannot seek");
    unsafe {
        bcrypt::decrypt_bcrypt(
            key,
            NTFS_HEADER,
            &mut reader,
            16,
            &mut BufWriter::new(&mut iv[..]),
        );
    }
    println!("Phase 1 has extracted IV for derivation: {:X?}", iv);

    // phase 3: decrypt the rest of the file with the derived IV

    reader.seek(SeekFrom::Start(offset)).expect("Cannot seek");
    writer.seek(SeekFrom::Start(0)).expect("Cannot seek");
    unsafe {
        bcrypt::decrypt_bcrypt(
            key,
            iv,
            &mut reader,
            file.metadata().unwrap().len() - offset,
            &mut writer,
        );
    }
    writer.flush().unwrap();
    println!("Decryption completed");
}
