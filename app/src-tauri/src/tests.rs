#[cfg(test)]
mod tests {
    use crate::protocol::*;

    #[test]
    fn test_ping_serialization() {
        let msg = VkMessage::new_ping(12345);
        let cbor = msg.to_cbor().expect("Failed to serialize");
        
        let decoded: VkMessage = VkMessage::from_cbor(&cbor).expect("Failed to deserialize");
        assert_eq!(decoded.msg_type, MSG_PING);
        assert_eq!(decoded.id, Some(12345));
        assert_eq!(decoded.payload, b"PING");
    }

    #[test]
    fn test_protocol_error_handling() {
        let invalid_cbor = vec![0xFF, 0x00, 0x01];
        let result = VkMessage::from_cbor(&invalid_cbor);
        assert!(result.is_err());
    }
}
