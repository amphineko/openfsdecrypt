use indicatif::{ProgressBar, ProgressStyle};

pub fn new_decrypt_progress_bar(length: u64) -> ProgressBar {
    ProgressBar::new(length).with_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes}",
        )
        .unwrap()
        .progress_chars("#-"),
    )
}
