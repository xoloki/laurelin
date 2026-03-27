use std::path::Path;

fn main() {
    let vk_path = Path::new("src/vk_generated.rs");
    if !vk_path.exists() {
        std::fs::write(
            vk_path,
            "// Stub — run `cd circuit && go run ./setup` to generate the real VK.\n\
             static REAL_VK: VerificationKey = VerificationKey {\n\
             \x20   alpha: [0u8; 64],\n\
             \x20   beta:  [0u8; 128],\n\
             \x20   gamma: [0u8; 128],\n\
             \x20   delta: [0u8; 128],\n\
             \x20   ic:    &[],\n\
             };\n",
        )
        .expect("failed to write stub vk_generated.rs");
        println!("cargo:warning=src/vk_generated.rs not found; wrote stub. Run `cd circuit && go run ./setup` to regenerate.");
    }
    println!("cargo:rerun-if-changed=src/vk_generated.rs");
}
