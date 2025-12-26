use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct VkMessage {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub msg_type: u8,
    pub payload: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
}

pub const MSG_PING: u8 = 0;
pub const MSG_PONG: u8 = 1;
pub const MSG_AUTH_CHALLENGE: u8 = 2;
pub const MSG_VAULT_LIST_REQ: u8 = 4;

impl VkMessage {
    pub fn new_ping(id: u32) -> Self {
        Self {
            version: 1,
            msg_type: MSG_PING,
            payload: b"PING".to_vec(),
            id: Some(id),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(data)
    }
}
