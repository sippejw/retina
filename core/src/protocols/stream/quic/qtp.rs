use num_enum::TryFromPrimitive;
use serde::Serialize;

use std::cmp::Ordering;

// Helper function to decode variable-length integers as defined in RFC 9000 Section 16
// https://www.rfc-editor.org/rfc/rfc9000#name-variable-length-integer-enc
fn var_int(i: &[u8]) -> (u64, &[u8]) {
    let mut v: u64 = i[0] as u64;
    let prefix = v >> 6;
    let length = 1 << prefix;
    v &= 0x3f;
    for &j in i.iter().take(length).skip(1) {
        v = (v << 8) | i[j as usize] as u64;
    }
    (v, &i[length..])
}

// Check if a transport parameter ID is a reserved (GREASEd) value.
// Defined by RFC 9000 Secion 18.1: https://www.rfc-editor.org/rfc/rfc9000#section-18.1
pub fn is_reserved(parameter_id: u64) -> bool {
    if parameter_id >= 27 {
        return (parameter_id - 27) % 31 == 0;
    }
    false
}

// Original Transport Parameter IDs as defined by RFC 9000 Section 18.2: // https://www.rfc-editor.org/rfc/rfc9000#section-18.2
// This could be expanded to include implementation specific parameters or future extensions.
#[derive(Clone, Debug, Serialize, TryFromPrimitive)]
#[repr(u64)]
pub enum TransportParameterId {
    OriginalDestinationConnectionId = 0x0000,
    MaxIdleTimeout = 0x0001,
    StatelessResetToken = 0x0002,
    MaxUdpPayloadSize = 0x0003,
    InitialMaxData = 0x0004,
    InitialMaxStreamDataBidiLocal = 0x0005,
    InitialMaxStreamDataBidiRemote = 0x0006,
    InitialMaxStreamDataUni = 0x0007,
    InitialMaxStreamsBidi = 0x0008,
    InitialMaxStreamsUni = 0x0009,
    AckDelayExponent = 0x000A,
    MaxAckDelay = 0x000B,
    DisableActiveMigration = 0x000C,
    PreferredAddress = 0x000D,
    ActiveConnectionIdLimit = 0x000E,
    InitialSourceConnectionId = 0x000F,
    RetrySourceConnectionId = 0x0010,
    VersionInformation = 0x0011,
    ParameterGrease = 0x001B,
    MaxDatagramFrameSize = 0x0020,
    GreaseQuicBit = 0x2AB2,
}

#[derive(Debug, Serialize, Clone)]
pub enum TransportParameter {
    OriginalDestinationConnectionId(Vec<u8>),
    MaxIdleTimeout {
        value: Vec<u8>,
        max_idle_timeout: u64,
    },
    StatelessResetToken([u8; 16]),
    MaxUdpPayloadSize {
        value: Vec<u8>,
        max_udp_payload_size: u64,
    },
    InitialMaxData {
        value: Vec<u8>,
        initial_max_data: u64,
    },
    InitialMaxStreamDataBidiLocal {
        value: Vec<u8>,
        initial_max_stream_data_bidi_local: u64,
    },
    InitialMaxStreamDataBidiRemote {
        value: Vec<u8>,
        initial_max_stream_data_bidi_remote: u64,
    },
    InitialMaxStreamDataUni {
        value: Vec<u8>,
        initial_max_stream_data_uni: u64,
    },
    InitialMaxStreamsBidi {
        value: Vec<u8>,
        initial_max_streams_bidi: u64,
    },
    InitialMaxStreamsUni {
        value: Vec<u8>,
        initial_max_streams_uni: u64,
    },
    AckDelayExponent {
        value: Vec<u8>,
        ack_delay_exponent: u64,
    },
    MaxAckDelay {
        value: Vec<u8>,
        max_ack_delay: u64,
    },
    DisableActiveMigration,
    PreferredAddress {
        ipv4_address: u32,
        ipv4_port: u16,
        ipv6_address: [u8; 16],
        ipv6_port: u16,
        connection_id: Vec<u8>,
        stateless_reset_token: [u8; 16],
    },
    ActiveConnectionIdLimit {
        value: Vec<u8>,
        active_connection_id_limit: u64,
    },
    InitialSourceConnectionId(Vec<u8>),
    RetrySourceConnectionId(Vec<u8>),
    VersionInformation {
        chosen_version: u32,
        supported_versions: Vec<u32>,
    },
    ParameterGrease {
        id: u64,
        value: Vec<u8>,
    },
    MaxDatagramFrameSize {
        value: Vec<u8>,
        max_datagram_frame_size: u64,
    },
    GreaseQuicBit,
    Unknown {
        id: u64,
        value: Vec<u8>,
    },
}

impl TransportParameter {
    // Returns the ID of the transport parameter as defined by RFC 9000 Section 18.2
    pub fn get_id(&self) -> u64 {
        match self {
            TransportParameter::OriginalDestinationConnectionId { .. } => {
                TransportParameterId::OriginalDestinationConnectionId as u64
            }
            TransportParameter::MaxIdleTimeout { .. } => {
                TransportParameterId::MaxIdleTimeout as u64
            }
            TransportParameter::StatelessResetToken { .. } => {
                TransportParameterId::StatelessResetToken as u64
            }
            TransportParameter::MaxUdpPayloadSize { .. } => {
                TransportParameterId::MaxUdpPayloadSize as u64
            }
            TransportParameter::InitialMaxData { .. } => {
                TransportParameterId::InitialMaxData as u64
            }
            TransportParameter::InitialMaxStreamDataBidiLocal { .. } => {
                TransportParameterId::InitialMaxStreamDataBidiLocal as u64
            }
            TransportParameter::InitialMaxStreamDataBidiRemote { .. } => {
                TransportParameterId::InitialMaxStreamDataBidiRemote as u64
            }
            TransportParameter::InitialMaxStreamDataUni { .. } => {
                TransportParameterId::InitialMaxStreamDataUni as u64
            }
            TransportParameter::InitialMaxStreamsBidi { .. } => {
                TransportParameterId::InitialMaxStreamsBidi as u64
            }
            TransportParameter::InitialMaxStreamsUni { .. } => {
                TransportParameterId::InitialMaxStreamsUni as u64
            }
            TransportParameter::AckDelayExponent { .. } => {
                TransportParameterId::AckDelayExponent as u64
            }
            TransportParameter::MaxAckDelay { .. } => TransportParameterId::MaxAckDelay as u64,
            TransportParameter::DisableActiveMigration => {
                TransportParameterId::DisableActiveMigration as u64
            }
            TransportParameter::PreferredAddress { .. } => {
                TransportParameterId::PreferredAddress as u64
            }
            TransportParameter::ActiveConnectionIdLimit { .. } => {
                TransportParameterId::ActiveConnectionIdLimit as u64
            }
            TransportParameter::InitialSourceConnectionId { .. } => {
                TransportParameterId::InitialSourceConnectionId as u64
            }
            TransportParameter::RetrySourceConnectionId { .. } => {
                TransportParameterId::RetrySourceConnectionId as u64
            }
            TransportParameter::VersionInformation { .. } => {
                TransportParameterId::VersionInformation as u64
            }
            TransportParameter::MaxDatagramFrameSize { .. } => {
                TransportParameterId::MaxDatagramFrameSize as u64
            }
            TransportParameter::GreaseQuicBit => TransportParameterId::GreaseQuicBit as u64,
            TransportParameter::ParameterGrease { .. } => {
                TransportParameterId::ParameterGrease as u64
            }
            TransportParameter::Unknown { id, .. } => *id,
        }
    }
}

impl PartialEq for TransportParameter {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for TransportParameter {}

impl PartialOrd for TransportParameter {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.get_id().cmp(&other.get_id()))
    }
}

impl Ord for TransportParameter {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_id().cmp(&other.get_id())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct QuicTransportParameters {
    pub parameters: Vec<TransportParameter>,
}

impl QuicTransportParameters {
    pub fn new(data: Vec<u8>) -> Self {
        let mut parameters = Vec::new();
        let mut data = data.as_slice();
        while !data.is_empty() {
            let (parameter_id, parameter_value, rest) = Self::parse_parameter(data);

            let parameter = if is_reserved(parameter_id) {
                TransportParameter::ParameterGrease {
                    id: parameter_id,
                    value: parameter_value.to_vec(),
                }
            } else {
                match TransportParameterId::try_from(parameter_id) {
                    Ok(TransportParameterId::OriginalDestinationConnectionId) => {
                        TransportParameter::OriginalDestinationConnectionId(
                            parameter_value.to_vec(),
                        )
                    }
                    Ok(TransportParameterId::MaxIdleTimeout) => {
                        TransportParameter::MaxIdleTimeout {
                            value: parameter_value.to_vec(),
                            max_idle_timeout: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::StatelessResetToken) => {
                        TransportParameter::StatelessResetToken(parameter_value.try_into().unwrap())
                    }
                    Ok(TransportParameterId::MaxUdpPayloadSize) => {
                        TransportParameter::MaxUdpPayloadSize {
                            value: parameter_value.to_vec(),
                            max_udp_payload_size: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxData) => {
                        TransportParameter::InitialMaxData {
                            value: parameter_value.to_vec(),
                            initial_max_data: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxStreamDataBidiLocal) => {
                        TransportParameter::InitialMaxStreamDataBidiLocal {
                            value: parameter_value.to_vec(),
                            initial_max_stream_data_bidi_local: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxStreamDataBidiRemote) => {
                        TransportParameter::InitialMaxStreamDataBidiRemote {
                            value: parameter_value.to_vec(),
                            initial_max_stream_data_bidi_remote: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxStreamDataUni) => {
                        TransportParameter::InitialMaxStreamDataUni {
                            value: parameter_value.to_vec(),
                            initial_max_stream_data_uni: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxStreamsBidi) => {
                        TransportParameter::InitialMaxStreamsBidi {
                            value: parameter_value.to_vec(),
                            initial_max_streams_bidi: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialMaxStreamsUni) => {
                        TransportParameter::InitialMaxStreamsUni {
                            value: parameter_value.to_vec(),
                            initial_max_streams_uni: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::AckDelayExponent) => {
                        TransportParameter::AckDelayExponent {
                            value: parameter_value.to_vec(),
                            ack_delay_exponent: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::MaxAckDelay) => TransportParameter::MaxAckDelay {
                        value: parameter_value.to_vec(),
                        max_ack_delay: var_int(parameter_value).0,
                    },
                    Ok(TransportParameterId::DisableActiveMigration) => {
                        TransportParameter::DisableActiveMigration
                    }
                    Ok(TransportParameterId::PreferredAddress) => {
                        todo!("Parse Preferred address")
                    }
                    Ok(TransportParameterId::ActiveConnectionIdLimit) => {
                        TransportParameter::ActiveConnectionIdLimit {
                            value: parameter_value.to_vec(),
                            active_connection_id_limit: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::InitialSourceConnectionId) => {
                        TransportParameter::InitialSourceConnectionId(parameter_value.to_vec())
                    }
                    Ok(TransportParameterId::RetrySourceConnectionId) => {
                        TransportParameter::RetrySourceConnectionId(parameter_value.to_vec())
                    }
                    Ok(TransportParameterId::VersionInformation) => {
                        todo!("Parse Version Information")
                    }
                    Ok(TransportParameterId::MaxDatagramFrameSize) => {
                        TransportParameter::MaxDatagramFrameSize {
                            value: parameter_value.to_vec(),
                            max_datagram_frame_size: var_int(parameter_value).0,
                        }
                    }
                    Ok(TransportParameterId::GreaseQuicBit) => TransportParameter::GreaseQuicBit,
                    Ok(TransportParameterId::ParameterGrease) => {
                        TransportParameter::ParameterGrease {
                            id: parameter_id,
                            value: parameter_value.to_vec(),
                        }
                    }
                    Err(err) => {
                        log::warn!("Failed to parse transport parameter: {:?}", err);
                        TransportParameter::Unknown {
                            id: parameter_id,
                            value: parameter_value.to_vec(),
                        }
                    }
                }
            };
            parameters.push(parameter);
            data = rest;
        }
        QuicTransportParameters { parameters }
    }

    // Parses the parameter ID, parameter length, and parameter value(s) from the given data slice.
    fn parse_parameter(data: &[u8]) -> (u64, &[u8], &[u8]) {
        let (parameter_id, data) = var_int(data);
        let (parameter_len, data) = var_int(data);
        let parameter_value = &data[..parameter_len as usize];
        let rest = &data[parameter_len as usize..];
        (parameter_id, parameter_value, rest)
    }
}
