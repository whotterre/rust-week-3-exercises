use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        // Construct a CompactSize from a u64 value
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Encode according to Bitcoin's CompactSize format:
        // [0x00–0xFC] => 1 byte
        // [0xFDxxxx] => 0xFD + u16 (2 bytes)
        // [0xFExxxxxxxx] => 0xFE + u32 (4 bytes)
        // [0xFFxxxxxxxxxxxxxxxx] => 0xFF + u64 (8 bytes)
        let mut bytes = Vec::new();
        match self.value {
            0..=0xFC => {
                // 0 - 252
                bytes.push(self.value as u8);
            }
            0xFD..=0xFFFF => {
                bytes.push(0xFD); // 253 - 65,535
                bytes.extend_from_slice(&(self.value as u16).to_le_bytes());
            }
            0x10000..=0xFFFFFFFF => {
                bytes.push(0xFE); // 65,536 - (2 ^ 32) - 1
                bytes.extend_from_slice(&(self.value as u32).to_le_bytes());
            }
            _ => {
                bytes.push(0xFF); // otherwise, 
                bytes.extend_from_slice(&self.value.to_le_bytes());
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Decode CompactSize, returning value and number of bytes consumed.
        // First check if bytes is empty.
        // Check that enough bytes are available based on prefix.
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        let prefix = bytes[0];
        match prefix {
            0xFD => {
                if bytes.len() == 3 {
                    return Err(BitcoinError::InsufficientBytes);
                } else {
                    // skip the prefix and take what follows?
                    let val = u16::from_le_bytes([bytes[1], bytes[2]]);
                    Ok((CompactSize::new(val as u64), 3))
                }
            }
            0xFE => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                } else {
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&bytes[1..5]);
                    let val = u32::from_le_bytes(buf);
                    Ok((CompactSize::new(val as u64), 5))
                }
            }

            0xFF => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[1..9]);
                let val = u64::from_le_bytes(buf);
                Ok((CompactSize::new(val), 9))
            }

            _ => Ok((CompactSize::new(prefix as u64), 1)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a hex-encoded string (32 bytes => 64 hex characters)
        let hex_str = hex::encode(self.0);
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Parse hex string into 32-byte array
        // Use `hex::decode`, validate length = 32
        let hex_string = String::deserialize(deserializer)?;

        let bytes = hex::decode(&hex_string)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Invalid Txid length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Failed to convert to 32-byte array"))?;

        Ok(Txid(array))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        // Create an OutPoint from raw txid bytes and output index
        Self {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize as: txid (32 bytes) + vout (4 bytes - 32bits, little-endian)
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.txid.0);
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Deserialize 36 bytes: txid[0..32], vout[32..36]
        // Return error if insufficient bytes
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&bytes[0..32]);

        let mut vout_bytes = [0u8; 4];
        vout_bytes.copy_from_slice(&bytes[32..36]);
        let vout = u32::from_le_bytes(vout_bytes);

        Ok((
            OutPoint {
                txid: Txid(txid_bytes),
                vout,
            },
            36,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        // Simple constructor
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Prefix with CompactSize (length), then raw bytes
        let mut result = Vec::new();
        let size_prefix = CompactSize::new(self.bytes.len() as u64);
        result.extend_from_slice(&size_prefix.to_bytes());
        result.extend_from_slice(&self.bytes);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Parse CompactSize prefix, then read that many bytes
        // Return error if not enough bytes
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        let (script_len, prefix_size) = match bytes[0] {
            0xfd => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
                (len, 3)
            }
            0xfe => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
                (len, 5)
            }
            0xff => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let len = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]) as usize;
                (len, 9)
            }
            n if n < 0xfd => (n as usize, 1),
            _ => return Err(BitcoinError::InsufficientBytes),
        };

        let total_bytes = prefix_size + script_len;

        if bytes.len() < total_bytes {
            return Err(BitcoinError::InsufficientBytes);
        }

        let script = Script {
            bytes: bytes[prefix_size..total_bytes].to_vec(),
        };

        Ok((script, total_bytes))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        // Allow &Script to be used as &[u8]
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        // Basic constructor
        TransactionInput {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize: OutPoint + Script (with CompactSize) + sequence (4 bytes LE)
        let serialized_output = self.previous_output.to_bytes();
        let script_sig = CompactSize::new(self.script_sig.len() as u64).to_bytes();
        let sequence = u32::to_le_bytes(self.sequence).to_vec();

        let mut concatenated_bytes = Vec::new();
        concatenated_bytes.extend_from_slice(&serialized_output);
        concatenated_bytes.extend_from_slice(&script_sig);
        concatenated_bytes.extend_from_slice(&self.script_sig.bytes);
        concatenated_bytes.extend_from_slice(&sequence);

        concatenated_bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Deserialize in order:
        // - OutPoint (36 bytes)
        // - Script (with CompactSize)
        // - Sequence (4 bytes)

        let (outpoint, outpoint_consumed) = OutPoint::from_bytes(bytes)?;
        let (script, script_consumed) = Script::from_bytes(&bytes[outpoint_consumed..])?;
        let sequence_start = outpoint_consumed + script_consumed;
        let sequence_bytes: [u8; 4] = bytes[sequence_start..sequence_start + 4]
            .try_into()
            .map_err(|_| BitcoinError::InsufficientBytes)?;
        let total_consumed = outpoint_consumed + script_consumed + 4;
        Ok((
            TransactionInput {
                previous_output: outpoint,
                script_sig: script,
                sequence: u32::from_le_bytes(sequence_bytes),
            },
            total_consumed,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        // Construct a transaction from parts
        BitcoinTransaction {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Format:
        // - version (4 bytes LE)
        // - CompactSize (number of inputs)
        // - each input serialized
        // - lock_time (4 bytes LE)
        let mut res: Vec<u8> = Vec::new();
        let version_bytes = self.version.to_le_bytes().to_vec();
        let c_size_bytes = CompactSize::new(self.inputs.len() as u64).to_bytes();
        let mut inputs_bytes: Vec<u8> = Vec::new();

        for input in &self.inputs {
            let transaction_bytes = input.to_bytes();
            inputs_bytes.extend_from_slice(&transaction_bytes);
        }

        let lock_time_bytes = self.lock_time.to_le_bytes().to_vec();

        res.extend_from_slice(&version_bytes);
        res.extend_from_slice(&c_size_bytes);
        res.extend_from_slice(&inputs_bytes);
        res.extend_from_slice(&lock_time_bytes);

        res
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Read version, CompactSize for input count
        // Parse inputs one by one
        // Read final 4 bytes for lock_time
        let mut offset = 0;

        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version_bytes: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        let version = u32::from_le_bytes(version_bytes);
        offset += 4;

        let (input_count, compact_consumed) = CompactSize::from_bytes(&bytes[offset..])?;
        offset += compact_consumed;
        let input_count = input_count.value as usize;

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let (input, input_consumed) = TransactionInput::from_bytes(&bytes[offset..])?;
            inputs.push(input);
            offset += input_consumed;
        }

        if bytes.len() < offset + 4 {
            // if the inputs vector is 0, then
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time_bytes: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        let lock_time = u32::from_le_bytes(lock_time_bytes);
        offset += 4;

        Ok((
            BitcoinTransaction {
                version,
                inputs,
                lock_time,
            },
            offset,
        ))
    }
}
impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format a user-friendly string showing version, inputs, lock_time
        // Display scriptSig length and bytes, and previous output info
        write!(f, "Version: {}\n", self.version)?;

        for input in &self.inputs {
            write!(f, "Previous Output Vout: {}\n", input.previous_output.vout)?;
        }

        write!(f, "Lock Time: {}", self.lock_time)
    }
}
