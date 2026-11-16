use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Dice a Cargo di rieseguire lo script solo se la DLL cambia
    println!("cargo:rerun-if-changed=libs/libfftw3-3.dll");

    // Trova la cartella di output (target/debug o target/release)
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = PathBuf::from(out_dir);
    // Risale dalla cartella 'out' fino alla cartella del profilo (es. target/release)
    let target_profile_dir = out_path
        .ancestors()
        .nth(3)
        .expect("Failed to find target profile directory")
        .to_path_buf();

    let dll_src = PathBuf::from("libs/libfftw3-3.dll");
    let dll_dst = target_profile_dir.join("libfftw3-3.dll");

    if dll_src.exists() {
        fs::copy(&dll_src, &dll_dst).expect("Failed to copy libfftw3-3.dll");
        println!("cargo:warning=Copied libfftw3-3.dll to {:?}", dll_dst);
    } else {
        panic!("libfftw3-3.dll not found at {:?}", dll_src);
    }
}