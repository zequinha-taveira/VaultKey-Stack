use serialport::{SerialPortType, UsbPortInfo};
use hidapi::HidApi;

pub const USBD_VID: u16 = 0x2E8A;
pub const USBD_PID: u16 = 0x000A;

#[derive(Debug)]
pub enum DeviceTransport {
    Serial(String),
    Hid(String),
}

pub fn find_vaultkey_device() -> Option<DeviceTransport> {
    // Try Serial first (CDC)
    let ports = serialport::available_ports().ok()?;
    for port in ports {
        if let SerialPortType::UsbPort(UsbPortInfo { vid, pid, .. }) = port.port_type {
            if vid == USBD_VID && pid == USBD_PID {
                return Some(DeviceTransport::Serial(port.port_name));
            }
        }
    }

    // Try HID
    if let Ok(api) = HidApi::new() {
        for device in api.device_list() {
            if device.vendor_id() == USBD_VID && device.product_id() == USBD_PID {
                return Some(DeviceTransport::Hid(device.path().to_string_lossy().into_owned()));
            }
        }
    }

    None
}
