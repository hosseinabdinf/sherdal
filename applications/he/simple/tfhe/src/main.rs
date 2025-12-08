use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

use std::mem::size_of_val;

// Helper function to convert bytes to KByte and Kbit
fn data_size(bytes: usize) -> (f64, f64) {
    let kb = bytes as f64 / 1024.0;
    let kbit = kb * 8.0;
    (kb, kbit)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 5u32;
    let clear_b = 3u32;

    // Encrypting the input data using the (private) client_key
    let encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

     // --- Size Measurement ---
    let clear_size_bytes = size_of_val(&clear_a);
    let (clear_size_kb, clear_size_kbit) = data_size(clear_size_bytes);
    let encrypted_stack_size_bytes = size_of_val(&encrypted_a);
    let (encrypted_stack_size_kb, encrypted_stack_size_kbit) = data_size(encrypted_stack_size_bytes);
    // Clear Variable Size
    println!("Clear Variable (`clear_a: u32`):");
    println!("  Size on stack: {} Bytes", clear_size_bytes);
    println!("  Size in KB:    {:.3} KByte", clear_size_kb);
    println!("  Size in Kbit:  {:.3} Kbit", clear_size_kbit);
    // Encrypted Variable Size
    println!("\nEncrypted Variable (`encrypted_a: FheUint32`):");
    println!("  Size on stack: {} Bytes", encrypted_stack_size_bytes);
    println!("  Size in KB:    {:.3} KByte", encrypted_stack_size_kb);
    println!("  Size in Kbit:  {:.3} Kbit", encrypted_stack_size_kbit);
    // On the server side:
    set_server_key(server_keys);

    // Clear equivalent computations: a * b = 15
    let ab = &encrypted_a * &encrypted_b;

    // Decrypting on the client side:
    let clear_res: u32 = ab.decrypt(&client_key);
    assert_eq!(clear_res, 15_u32);
    println!("Result: {}", clear_res);
    Ok(())
}