use std::path::Path;

fn stub_vk(path: &str, var_name: &str) {
    let p = Path::new(path);
    if !p.exists() {
        std::fs::write(
            p,
            format!(
                "// Stub — run `cd circuit && go run ./setup` to generate the real VK.\n\
                 static {var_name}: VerificationKey = VerificationKey {{\n\
                 \x20   alpha: [0u8; 64],\n\
                 \x20   beta:  [0u8; 128],\n\
                 \x20   gamma: [0u8; 128],\n\
                 \x20   delta: [0u8; 128],\n\
                 \x20   ic:    &[],\n\
                 }};\n"
            ),
        )
        .unwrap_or_else(|_| panic!("failed to write stub {path}"));
        println!("cargo:warning={path} not found; wrote stub. Run `cd circuit && go run ./setup` to regenerate.");
    }
    println!("cargo:rerun-if-changed={path}");
}

fn main() {
    stub_vk("src/transfer_vk_generated.rs", "TRANSFER_VK");
    stub_vk("src/deposit_vk_generated.rs",  "DEPOSIT_VK");
    stub_vk("src/withdraw_vk_generated.rs", "WITHDRAW_VK");
}
