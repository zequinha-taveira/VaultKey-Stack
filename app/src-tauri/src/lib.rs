mod usb;
mod protocol;
#[cfg(test)]
mod tests;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn derive_key(pin: String, salt: Vec<u8>) -> Result<Vec<u8>, String> {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };
    use zeroize::Zeroizing;

    let pin = Zeroizing::new(pin);
    
    // ...
    let mut output = [0u8; 32];
    let mut output = Zeroizing::new(output);
    let salt_bytes = salt.as_slice();
    
    // We'll use the low-level API for direct output
    let context = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(2048, 3, 1, Some(32)).map_err(|e| e.to_string())?,
    );
    
    context.hash_password_into(pin.as_bytes(), salt_bytes, &mut *output).map_err(|e| e.to_string())?;
    
    Ok(output.to_vec())
}

#[tauri::command]
async fn send_command(msg_type: u8, payload: Vec<u8>) -> Result<Vec<u8>, String> {
    let transport = usb::find_vaultkey_device().ok_or("Device not found")?;
    
    match transport {
        usb::DeviceTransport::Serial(port_name) => {
            let mut port = serialport::new(port_name, 115_200)
                .timeout(std::time::Duration::from_millis(1000))
                .open()
                .map_err(|e| e.to_string())?;

            let msg = protocol::VkMessage {
                version: 1,
                msg_type,
                payload,
                id: Some(rand::random()),
            };

            let cbor = msg.to_cbor().map_err(|e| e.to_string())?;
            port.write_all(&cbor).map_err(|e| e.to_string())?;

            let mut res_buf = [0u8; 256];
            let len = port.read(&mut res_buf).map_err(|e| e.to_string())?;
            
            let res_msg = protocol::VkMessage::from_cbor(&res_buf[..len]).map_err(|e| e.to_string())?;
            Ok(res_msg.payload)
        }
        usb::DeviceTransport::Hid(_) => Err("HID transport not yet fully implemented for commands".to_string()),
    }
}

#[tauri::command]
async fn get_totp() -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let mut payload = timestamp.to_ne_bytes().to_vec();
    
    // VK_MSG_TOTP_REQ = 12
    let response = send_command(12, payload).await?;
    Ok(String::from_utf8_lossy(&response).to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, get_device_status, send_command, derive_key, get_totp])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
