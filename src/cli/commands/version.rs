//! Version command implementation

pub fn print_version(verbose: bool) {
    let version = env!("CARGO_PKG_VERSION");
    if verbose {
        println!("authsock-warden {}", version);
        println!(
            "rustc {}",
            option_env!("RUSTC_VERSION").unwrap_or("unknown")
        );
    } else {
        println!("authsock-warden {}", version);
    }
}
