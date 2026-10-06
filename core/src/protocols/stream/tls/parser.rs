//! TLS handshake parser.
//!
//! The TLS handshake parser uses a [fork](https://github.com/thegwan/tls-parser) of the
//! [tls-parser](https://docs.rs/tls-parser/latest/tls_parser/) crate to parse the handshake phase
//! of a TLS connection. It maintains TLS state, stores selected parameters, and handles
//! defragmentation.
//!
//! Adapted from [the Rusticata TLS
//! parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs).

use super::handshake::{
    Certificate, ClientDHParams, ClientECDHParams, ClientHello, ClientKeyExchange, ClientRSAParams,
    KeyShareEntry, ServerDHParams, ServerECDHParams, ServerHello, ServerKeyExchange,
    ServerRSAParams,
};
use super::Tls;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::quic::qtp::QuicTransportParameters;
use crate::protocols::stream::tls::EncryptedClientHello;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

use tls_parser::*;

/// Parses a single TLS handshake per connection.
#[derive(Debug)]
pub struct TlsParser {
    sessions: Vec<Tls>,
}

impl TlsParser {}

impl Default for TlsParser {
    fn default() -> Self {
        TlsParser {
            sessions: vec![Tls::new()],
        }
    }
}

impl ConnParsable for TlsParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser tls");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.sessions[0].parse_tcp_level(data, pdu.dir)
        } else {
            log::warn!("Malformed packet");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() <= 2 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            // First byte is record type (between 0x14 and 0x17, 0x16 is handhake) Second is TLS
            // version major (0x3) Third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
            // Does not support versions <= SSLv2
            match (data[0], data[1], data[2]) {
                (0x14..=0x17, 0x03, 0..=3) => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|tls| Session {
            data: SessionData::Tls(Box::new(tls)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|tls| Session {
                data: SessionData::Tls(Box::new(tls)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Stop
    }
}

// ------------------------------------------------------------

impl Tls {
    /// Allocate a new TLS handshake instance.
    pub(crate) fn new() -> Tls {
        Tls {
            client_hello: None,
            server_hello: None,
            server_certificates: vec![],
            client_certificates: vec![],
            server_key_exchange: None,
            client_key_exchange: None,
            raw_data: vec![],
            raw_data_len: 0,
            raw_data_overflow: false,
            state: TlsState::None,
            client_first_record_parsed: false,
            tcp_buffer: [vec![], vec![]],
            record_buffer: [vec![], vec![]],
        }
    }

    /// Parse a ClientHello message. Returns `false`, leaving `client_hello` unset, if its
    /// extension block does not parse completely: such a ClientHello is truncated or was
    /// completed with bytes that do not belong to it.
    pub(crate) fn parse_handshake_clienthello(&mut self, content: &TlsClientHelloContents) -> bool {
        let mut client_hello = ClientHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suites: content.ciphers.to_vec(),
            compression_algs: content.comp.to_vec(),
            ..ClientHello::default()
        };

        let ext = parse_tls_client_hello_extensions(content.ext.unwrap_or(b""));
        log::trace!("client extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                // tls-parser stops at the first extension that fails to parse and returns the
                // rest unparsed
                if !rem.is_empty() {
                    log::debug!("ClientHello extensions not entirely parsed, ignoring it");
                    return false;
                }
                for extension in ext_lst {
                    client_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::SNI(ref v) => {
                            if !v.is_empty() {
                                let sni = v[0].1;
                                client_hello.server_name = Some(match std::str::from_utf8(sni) {
                                    Ok(name) => name.to_string(),
                                    Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(sni)),
                                });
                            }
                        }
                        TlsExtension::SupportedGroups(ref v) => {
                            client_hello.supported_groups = v.clone();
                        }
                        TlsExtension::EcPointFormats(v) => {
                            client_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::SignatureAlgorithms(ref v) => {
                            client_hello.signature_algs = v.clone();
                        }
                        TlsExtension::ALPN(ref v) => {
                            for proto in v {
                                client_hello.alpn_protocols.push(
                                    match std::str::from_utf8(proto) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => {
                                            format!("<Invalid UTF-8: {}>", hex::encode(proto))
                                        }
                                    },
                                );
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Client Shares: {:?}", v);
                            client_hello.key_shares = v
                                .iter()
                                .map(|k| KeyShareEntry {
                                    group: k.group,
                                    kx_data: k.kx.to_vec(),
                                })
                                .collect();
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            client_hello.supported_versions = v.clone();
                        }
                        TlsExtension::PskExchangeModes(ref v) => {
                            client_hello.psk_exchange_modes = v.clone();
                        }
                        TlsExtension::CompressCertificate(v) => {
                            client_hello.compress_certificate = v.to_vec();
                        }
                        TlsExtension::RecordSizeLimit(v) => {
                            client_hello.record_size_limit = Some(v);
                        }
                        TlsExtension::EncryptedClientHello { ch_type, ciphersuite, config_id, enc, payload } => {
                            client_hello.encrypted_client_hello = Some(EncryptedClientHello {
                                ch_type,
                                ciphersuite,
                                config_id,
                                enc: enc.to_vec(),
                                payload: payload.to_vec(),
                            });
                        }
                        TlsExtension::QuicTransportParameters(v) => {
                            client_hello.quic_transport_parameters =
                                QuicTransportParameters::new(v.to_vec()).ok();
                        }
                        _ => (),
                    }
                }
            }
            e => {
                log::debug!(
                    "Could not parse ClientHello extensions, ignoring it: {:?}",
                    e
                );
                return false;
            }
        };
        self.client_hello = Some(client_hello);
        true
    }

    /// Parse a ServerHello message.
    fn parse_handshake_serverhello(&mut self, content: &TlsServerHelloContents) {
        let mut server_hello = ServerHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suite: content.cipher,
            compression_alg: content.compression,
            ..ServerHello::default()
        };

        let ext = parse_tls_server_hello_extensions(content.ext.unwrap_or(b""));
        log::debug!("server_hello extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    server_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::EcPointFormats(v) => {
                            server_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::ALPN(ref v) => {
                            if !v.is_empty() {
                                server_hello.alpn_protocol =
                                    Some(match std::str::from_utf8(v[0]) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(v[0])),
                                    });
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Server Share: {:?}", v);
                            if !v.is_empty() {
                                server_hello.key_share = Some(KeyShareEntry {
                                    group: v[0].group,
                                    kx_data: v[0].kx.to_vec(),
                                });
                            }
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            if !v.is_empty() {
                                server_hello.selected_version = Some(v[0]);
                            }
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.server_hello = Some(server_hello);
    }

    /// Parse a Certificate message.
    fn parse_handshake_certificate(&mut self, content: &TlsCertificateContents, direction: bool) {
        log::trace!("cert chain length: {}", content.cert_chain.len());
        if direction {
            // client -> server
            for cert in &content.cert_chain {
                self.client_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        } else {
            // server -> client
            for cert in &content.cert_chain {
                self.server_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        }
    }

    /// Parse a ServerKeyExchange message.
    fn parse_handshake_serverkeyexchange(&mut self, content: &TlsServerKeyExchangeContents) {
        log::trace!("SKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_sig, ref parsed)) = parse_server_ecdh_params(content.parameters) {
                        if let ECParametersContent::NamedGroup(curve) =
                            parsed.curve_params.params_content
                        {
                            let ecdh_params = ServerECDHParams {
                                curve,
                                kx_data: parsed.public.point.to_vec(),
                            };
                            self.server_key_exchange = Some(ServerKeyExchange::Ecdh(ecdh_params));
                        };
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_sig, ref parsed)) = parse_server_dh_params(content.parameters) {
                        let dh_params = ServerDHParams {
                            prime: parsed.dh_p.to_vec(),
                            generator: parsed.dh_g.to_vec(),
                            kx_data: parsed.dh_ys.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_sig, ref parsed)) = parse_server_rsa_params(content.parameters) {
                        let rsa_params = ServerRSAParams {
                            modulus: parsed.modulus.to_vec(),
                            exponent: parsed.exponent.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.server_key_exchange =
                        Some(ServerKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
    }

    /// Parse a ClientKeyExchange message.
    fn parse_handshake_clientkeyexchange(&mut self, content: &TlsClientKeyExchangeContents) {
        log::trace!("CKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_rem, ref parsed)) = parse_client_ecdh_params(content.parameters) {
                        let ecdh_params = ClientECDHParams {
                            kx_data: parsed.ecdh_yc.point.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Ecdh(ecdh_params));
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_rem, ref parsed)) = parse_client_dh_params(content.parameters) {
                        let dh_params = ClientDHParams {
                            kx_data: parsed.dh_yc.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_rem, ref parsed)) = parse_client_rsa_params(content.parameters) {
                        let rsa_params = ClientRSAParams {
                            encrypted_pms: parsed.data.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.client_key_exchange =
                        Some(ClientKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
        //self.client_key_exchange = Some(client_key_exchange);
    }

    /// Parse a TLS message.
    pub(crate) fn parse_message_level(&mut self, msg: &TlsMessage, direction: bool) -> ParseResult {
        log::trace!("parse_message_level {:?}", msg);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        }

        // update state machine
        match tls_state_transition(self.state, msg, direction) {
            Ok(s) => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
            }
        };
        log::trace!("TLS new state: {:?}", self.state);

        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => match *m {
                // Keep only the client's first ClientHello, the first record of its TCP stream:
                // one parsed from server bytes is not the client's, and a later one (after a
                // HelloRetryRequest) must neither replace the first nor stand in for it when the
                // first could not be parsed
                TlsMessageHandshake::ClientHello(ref content)
                    if direction
                        && self.client_hello.is_none()
                        && !self.client_first_record_parsed =>
                {
                    if self.parse_handshake_clienthello(content) {
                        // Client's first flight parsed: deliver now and drop the
                        // per-connection parser state
                        #[cfg(feature = "client_hello_done")]
                        return ParseResult::Done(0);
                    }
                }
                TlsMessageHandshake::ServerHello(ref content) => {
                    self.parse_handshake_serverhello(content);
                    // The server answered a ClientHello that was not parsed (part of it was
                    // missed or it was rejected), so none will come: stop rather than keep
                    // tracking the connection, whose missing client bytes would leave every
                    // later client segment waiting in reassembly
                    #[cfg(feature = "client_hello_done")]
                    if !direction && self.client_hello.is_none() {
                        return ParseResult::Done(0);
                    }
                }
                TlsMessageHandshake::Certificate(ref content) => {
                    self.parse_handshake_certificate(content, direction);
                }
                TlsMessageHandshake::ServerKeyExchange(ref content) => {
                    self.parse_handshake_serverkeyexchange(content);
                }
                TlsMessageHandshake::ClientKeyExchange(ref content) => {
                    self.parse_handshake_clientkeyexchange(content);
                }

                _ => (),
            },
            TlsMessage::Alert(ref a) => {
                if a.severity == TlsAlertSeverity::Fatal {
                    return ParseResult::Done(0);
                }
            }
            _ => (),
        }

        ParseResult::Continue(0)
    }

    /// Parse a TLS record.
    pub(crate) fn parse_record_level(
        &mut self,
        record: &TlsRawRecord<'_>,
        direction: bool,
    ) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);

        log::trace!("parse_record_level ({} bytes)", record.data.len());
        log::trace!("{:?}", record.hdr);
        // log::trace!("{:?}", record.data);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        }

        // only parse some message types (the Content type, first byte of TLS record)
        match record.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake => (),
            TlsRecordType::Alert => (),
            _ => return ParseResult::Continue(0),
        }

        // Check if a record is being defragmented
        let dir = direction as usize;
        let record_buffer = match self.record_buffer[dir].len() {
            0 => record.data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.record_buffer[dir].len() + record.data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.record_buffer[dir].split_off(0);
                v.extend_from_slice(record.data);
                v.as_slice()
            }
        };

        // TODO: record may be compressed Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer, &record.hdr) {
            Ok((rem, ref msg_list)) => {
                // Handshake messages lie back to back: a 1-byte type, a 3-byte body length,
                // then the body
                let mut handshake_msgs = record_buffer;
                for msg in msg_list {
                    if let TlsMessage::Handshake(ref m) = *msg {
                        let body_len = u32::from_be_bytes([
                            0,
                            handshake_msgs[1],
                            handshake_msgs[2],
                            handshake_msgs[3],
                        ]) as usize;
                        handshake_msgs = &handshake_msgs[4 + body_len..];
                        // tls-parser ignores ClientHello bytes it could not parse, e.g. an
                        // extension block whose length overruns the message (ext=None)
                        if let TlsMessageHandshake::ClientHello(ref content) = *m {
                            if client_hello_len(content) != body_len {
                                log::debug!("ClientHello not entirely parsed, ignoring it");
                                continue;
                            }
                        }
                    }
                    status = self.parse_message_level(msg, direction);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                if !rem.is_empty() {
                    log::debug!("warn: extra bytes in TLS record: {:?}", rem);
                };
            }
            Err(Err::Incomplete(needed)) => {
                log::trace!(
                    "Defragmentation required (TLS record), missing {:?} bytes",
                    needed
                );
                self.record_buffer[dir].extend_from_slice(record.data);
            }
            Err(_e) => {
                log::debug!("warn: parse_tls_record_with_header failed");
                return ParseResult::Skipped;
            }
        };

        status
    }

    /// Parse a TCP segment, handling TCP chunks fragmentation.
    pub(crate) fn parse_tcp_level(&mut self, data: &[u8], direction: bool) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);
        let dir = direction as usize;
        log::trace!("parse_tcp_level ({} bytes)", data.len());
        log::trace!("defrag buffer size: {}", self.tcp_buffer[dir].len());

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        };
        // Keep the raw client -> server segments until the ClientHello has been parsed
        // (direction == true is originator -> responder, i.e. client -> server, as TCP
        // connections are only created on SYN). Once either cap would be exceeded the
        // capture is abandoned for good and what was stored is released, so `raw_data`
        // is either the complete contiguous prefix or empty.
        if direction && self.client_hello.is_none() && !self.raw_data_overflow {
            if self.raw_data_len + data.len() <= Tls::MAX_RAW_DATA
                && self.raw_data.len() < Tls::MAX_RAW_SEGMENTS
            {
                self.raw_data_len += data.len();
                self.raw_data.push(data.to_vec());
            } else {
                self.raw_data_overflow = true;
                self.raw_data_len = 0;
                self.raw_data = vec![];
            }
        }
        // Check if TCP data is being defragmented. Each direction has its own buffer, so a
        // record split across segments is only ever completed with bytes from the same side.
        let tcp_buffer = match self.tcp_buffer[dir].len() {
            0 => data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.tcp_buffer[dir].len() + data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.tcp_buffer[dir].split_off(0);
                v.extend_from_slice(data);
                v.as_slice()
            }
        };
        let mut cur_data = tcp_buffer;
        while !cur_data.is_empty() {
            // parse each TLS record in the TCP segment (there could be multiple)
            match parse_tls_raw_record(cur_data) {
                Ok((rem, ref record)) => {
                    cur_data = rem;
                    status = self.parse_record_level(record, direction);
                    self.client_first_record_parsed |= direction;
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                Err(Err::Incomplete(needed)) => {
                    log::trace!(
                        "Defragmentation required (TCP level), missing {:?} bytes",
                        needed
                    );
                    self.tcp_buffer[dir].extend_from_slice(cur_data);
                    break;
                }
                Err(_e) => {
                    log::debug!("warn: Parsing raw record failed");
                    self.client_first_record_parsed |= direction;
                    break;
                }
            }
        }
        status
    }
}

/// Number of ClientHello body bytes accounted for by its parsed fields.
fn client_hello_len(content: &TlsClientHelloContents) -> usize {
    2 + content.random.len()
        + 1
        + content.session_id.map_or(0, |sid| sid.len())
        + 2
        + 2 * content.ciphers.len()
        + 1
        + content.comp.len()
        + content.ext.map_or(0, |ext| 2 + ext.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLS-record-shaped segment that never completes a handshake message
    /// (handshake record header announcing more bytes than delivered).
    fn partial_record(len: usize) -> Vec<u8> {
        let mut seg = vec![0x16, 0x03, 0x01, 0xff, 0xff];
        seg.resize(len, 0);
        seg
    }

    #[test]
    fn raw_data_keeps_client_segments_until_client_hello() {
        let mut tls = Tls::new();
        tls.parse_tcp_level(&partial_record(1400), true);
        tls.parse_tcp_level(&partial_record(1400), false); // server side is never kept
        tls.parse_tcp_level(&partial_record(300), true);
        assert_eq!(tls.raw_data.len(), 2);
        assert_eq!(tls.raw_data_len, 1700);
    }

    #[test]
    fn raw_data_is_dropped_entirely_when_a_cap_is_exceeded() {
        // Byte cap: the segment that would cross 64 KiB discards everything.
        let mut tls = Tls::new();
        for _ in 0..46 {
            tls.parse_tcp_level(&partial_record(1400), true);
        }
        assert_eq!(tls.raw_data.len(), 46);
        tls.parse_tcp_level(&partial_record(1400), true); // 47 × 1400 > 65536
        assert!(tls.raw_data.is_empty());
        assert!(tls.raw_data_overflow);
        tls.parse_tcp_level(&partial_record(10), true); // sticky
        assert!(tls.raw_data.is_empty());

        // Segment-count cap: a trickle of tiny segments stops at MAX_RAW_SEGMENTS.
        let mut tls = Tls::new();
        for _ in 0..Tls::MAX_RAW_SEGMENTS {
            tls.parse_tcp_level(&partial_record(6), true);
        }
        assert_eq!(tls.raw_data.len(), Tls::MAX_RAW_SEGMENTS);
        tls.parse_tcp_level(&partial_record(6), true);
        assert!(tls.raw_data.is_empty());
        assert!(tls.raw_data_overflow);
    }

    const MSS: usize = 1460;

    /// The bytes each side sent on one real TLS connection (see testdata/).
    struct Transcript {
        name: String,
        client: Vec<u8>,
        server: Vec<u8>,
        /// JA3 string of the client's first ClientHello, computed without tls-parser
        ja3: String,
    }

    impl Transcript {
        /// The client's first TLS record, which holds its ClientHello.
        fn client_hello(&self) -> &[u8] {
            &self.client[..5 + u16::from_be_bytes([self.client[3], self.client[4]]) as usize]
        }

        /// What the client sent after its ClientHello record.
        fn client_rest(&self) -> &[u8] {
            &self.client[self.client_hello().len()..]
        }
    }

    fn transcripts(tsv: &str) -> Vec<Transcript> {
        tsv.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                Transcript {
                    name: fields[0].to_string(),
                    client: hex::decode(fields[1]).unwrap(),
                    server: hex::decode(fields[2]).unwrap(),
                    ja3: fields[3].to_string(),
                }
            })
            .collect()
    }

    fn corpus() -> Vec<Transcript> {
        transcripts(include_str!("testdata/client_hellos.tsv"))
    }

    /// Transcripts whose server answered the first ClientHello with a HelloRetryRequest.
    fn corpus_hrr() -> Vec<Transcript> {
        transcripts(include_str!("testdata/client_hellos_hrr.tsv"))
    }

    fn transcript(name: &str) -> Transcript {
        corpus().into_iter().find(|t| t.name == name).unwrap()
    }

    /// One direction's bytes cut into MSS-sized segment payloads (`true` is client to server).
    fn segments(dir: bool, data: &[u8]) -> Vec<(bool, &[u8])> {
        data.chunks(MSS).map(|chunk| (dir, chunk)).collect()
    }

    /// Feeds segment payloads to a new parser in the order reassembly delivers them, until the
    /// parser is done.
    fn deliver(payloads: &[(bool, &[u8])]) -> Tls {
        let mut tls = Tls::new();
        for &(dir, data) in payloads {
            if let ParseResult::Done(_) = tls.parse_tcp_level(data, dir) {
                break;
            }
        }
        tls
    }

    /// Everything parsed from a ClientHello, for comparing parses.
    fn fields(client_hello: &Option<ClientHello>) -> String {
        format!("{:?}", client_hello)
    }

    /// The transcript's ClientHello parsed from its intact record, after checking its JA3.
    fn intact(t: &Transcript) -> String {
        let tls = deliver(&[(true, t.client_hello())]);
        assert_eq!(tls.ja3_str(), t.ja3, "{}", t.name);
        fields(&tls.client_hello)
    }

    #[test]
    fn intact_client_hellos() {
        for t in corpus().iter().chain(&corpus_hrr()) {
            let want = intact(t);
            // MSS-sized segments (two for a post-quantum ClientHello), then the server's reply
            let mut payloads = segments(true, t.client_hello());
            payloads.extend(segments(false, &t.server));
            payloads.extend(segments(true, t.client_rest()));
            assert_eq!(fields(&deliver(&payloads).client_hello), want, "{}", t.name);
        }
    }

    #[test]
    fn client_hello_split_at_any_byte() {
        for t in corpus() {
            let want = intact(&t);
            let ch = t.client_hello();
            for k in 1..ch.len() {
                let tls = deliver(&[(true, &ch[..k]), (true, &ch[k..])]);
                assert_eq!(fields(&tls.client_hello), want, "{} split at {}", t.name, k);
            }
        }
    }

    #[test]
    fn server_bytes_before_second_segment_are_not_spliced() {
        // Only transcripts whose server replied with a handshake: a server alert that
        // arrives before the ClientHello is complete ends parsing without one. With
        // client_hello_done, so does the server's ServerHello.
        let want_none = cfg!(feature = "client_hello_done");
        for t in corpus().iter().filter(|t| t.server.first() == Some(&0x16)) {
            let want = if want_none { fields(&None) } else { intact(t) };
            let ch = t.client_hello();
            for k in 1..ch.len() {
                let mut payloads = vec![(true, &ch[..k])];
                payloads.extend(segments(false, &t.server));
                payloads.push((true, &ch[k..]));
                let tls = deliver(&payloads);
                assert_eq!(fields(&tls.client_hello), want, "{} split at {}", t.name, k);
            }
        }
    }

    #[cfg(feature = "client_hello_done")]
    #[test]
    fn server_hello_before_client_hello_ends_parsing() {
        // Segment 2 of the ClientHello was not captured, but the server answered it
        for t in corpus().iter().filter(|t| t.server.first() == Some(&0x16)) {
            let ch = t.client_hello();
            let server_hello_len = 5 + u16::from_be_bytes([t.server[3], t.server[4]]) as usize;
            let mut tls = Tls::new();
            assert_eq!(
                tls.parse_tcp_level(&ch[..ch.len() / 2], true),
                ParseResult::Continue(0)
            );
            assert_eq!(
                tls.parse_tcp_level(&t.server[..server_hello_len], false),
                ParseResult::Done(0),
                "{}",
                t.name
            );
            assert!(tls.client_hello.is_none());
            assert!(tls.server_hello.is_some());
        }
    }

    #[test]
    fn client_hello_missing_its_second_segment_is_not_completed() {
        for t in corpus().iter().filter(|t| !t.server.is_empty()) {
            let ch = t.client_hello();
            for k in 1..ch.len() {
                let mut payloads = vec![(true, &ch[..k])];
                payloads.extend(segments(false, &t.server));
                let tls = deliver(&payloads);
                assert!(tls.client_hello.is_none(), "{} cut at {}", t.name, k);
            }
        }
    }

    #[test]
    fn server_stream_shifted_by_missed_syn_ack_is_not_spliced() {
        // A missed SYN-ACK used to make reassembly drop the server's first byte, so its
        // bytes started 03 03 00 7a 02 instead of 16 03 03 00 7a 02
        for t in corpus().iter().filter(|t| t.server.len() > 1) {
            let want = intact(t);
            let ch = t.client_hello();
            for k in 1..ch.len() {
                let mut payloads = vec![(true, &ch[..k])];
                payloads.extend(segments(false, &t.server[1..]));
                let tls = deliver(&payloads);
                assert!(tls.client_hello.is_none(), "{} cut at {}", t.name, k);

                payloads.push((true, &ch[k..]));
                let tls = deliver(&payloads);
                assert_eq!(fields(&tls.client_hello), want, "{} split at {}", t.name, k);
            }
        }
    }

    #[test]
    fn hello_retry_request_keeps_first_client_hello() {
        for t in corpus_hrr() {
            let want = intact(&t);
            let hello = segments(true, t.client_hello());
            let rest = segments(true, t.client_rest());
            let server = segments(false, &t.server);
            let shifted_server = segments(false, &t.server[1..]);
            for (case, payloads) in [
                ("both sides", [&hello[..], &server[..], &rest[..]].concat()),
                ("client side only", [&hello[..], &rest[..]].concat()),
                (
                    "server shifted",
                    [&hello[..], &shifted_server[..], &rest[..]].concat(),
                ),
            ] {
                let tls = deliver(&payloads);
                assert_eq!(fields(&tls.client_hello), want, "{}: {}", t.name, case);
            }
        }
    }

    #[test]
    fn later_client_hello_does_not_stand_in_for_a_lost_first_one() {
        for t in corpus_hrr() {
            // CCS, then the second ClientHello
            let rest = t.client_rest();

            // First ClientHello split across two TLS records, which is not parsed
            let handshake = &t.client_hello()[5..];
            let (head, tail) = handshake.split_at(handshake.len() / 2);
            let records = [handshake_record(head), handshake_record(tail)].concat();
            let tls = deliver(&[(true, &records), (true, rest)]);
            assert!(tls.client_hello.is_none(), "{}: split records", t.name);

            // First bytes of the first ClientHello not seen
            let tls = deliver(&[(true, &t.client_hello()[2..]), (true, rest)]);
            assert!(tls.client_hello.is_none(), "{}: cut", t.name);
        }
    }

    #[test]
    fn client_hello_sent_by_server_is_ignored() {
        let t = transcript("utls_chrome133__default");
        let ch = t.client_hello();
        assert!(deliver(&[(false, ch)]).client_hello.is_none());
        let tls = deliver(&[(false, ch), (true, ch)]);
        assert_eq!(fields(&tls.client_hello), intact(&t));
    }

    #[cfg(not(feature = "client_hello_done"))]
    #[test]
    fn both_sides_reassemble_records_independently() {
        // Each side's first record is split, and the other side's bytes arrive in between
        let t = transcript("go_stdlib__tls12");
        let (ch, server) = (t.client_hello(), &t.server);
        let tls = deliver(&[
            (true, &ch[..MSS]),
            (false, &server[..40]),
            (true, &ch[MSS..]),
            (false, &server[40..]),
        ]);
        assert_eq!(fields(&tls.client_hello), intact(&t));
        assert_eq!(tls.cipher(), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(tls.server_certificates.len(), 1);
    }

    /// Splits a ClientHello record into its body up to the extension block, and the extensions.
    fn split_client_hello(record: &[u8]) -> (&[u8], &[u8]) {
        let body = &record[9..];
        let mut len = 2 + 32; // version, random
        len += 1 + body[len] as usize; // session id
        len += 2 + u16::from_be_bytes([body[len], body[len + 1]]) as usize; // cipher suites
        len += 1 + body[len] as usize; // compression methods
        (&body[..len], &body[len + 2..])
    }

    /// A ClientHello body: `head`, then an extension block declared `ext_len` bytes long that
    /// holds `exts`.
    fn with_extensions(head: &[u8], ext_len: usize, exts: &[u8]) -> Vec<u8> {
        [head, &(ext_len as u16).to_be_bytes()[..], exts].concat()
    }

    /// A TLS handshake record carrying `fragment`.
    fn handshake_record(fragment: &[u8]) -> Vec<u8> {
        [
            &[0x16, 0x03, 0x01][..],
            &(fragment.len() as u16).to_be_bytes(),
            fragment,
        ]
        .concat()
    }

    /// A TLS record holding one ClientHello with the given body.
    fn client_hello_record(body: &[u8]) -> Vec<u8> {
        handshake_record(&[&[0x01][..], &(body.len() as u32).to_be_bytes()[1..], body].concat())
    }

    #[test]
    fn client_hello_with_unparsed_extensions_is_rejected() {
        let t = transcript("utls_chrome120__default");
        let (head, exts) = split_client_hello(t.client_hello());
        let parse = |body: &[u8]| deliver(&[(true, &client_hello_record(body))]).client_hello;
        let body = with_extensions(head, exts.len(), exts);
        assert_eq!(client_hello_record(&body), t.client_hello());

        // Last extension's data runs past the extension block (key_share declaring 0x500 bytes)
        let truncated = [exts, &[0x00, 0x33, 0x05, 0x00, 0x01][..]].concat();
        assert!(parse(&with_extensions(head, truncated.len(), &truncated)).is_none());

        // An extension whose contents do not parse (psk_key_exchange_modes listing 5 modes in
        // 1 byte)
        let bad = [exts, &[0x00, 0x2d, 0x00, 0x02, 0x05, 0x01][..]].concat();
        assert!(parse(&with_extensions(head, bad.len(), &bad)).is_none());

        // Extension block declared longer than the ClientHello: tls-parser gives ext=None
        assert!(parse(&with_extensions(head, exts.len() + 1, exts)).is_none());

        // Bytes after the extension block
        assert!(parse(&[&body[..], &[0x00][..]].concat()).is_none());
    }

    #[test]
    fn client_hello_without_extensions_is_kept() {
        let t = transcript("utls_chrome120__default");
        let (head, _) = split_client_hello(t.client_hello());
        let ch = deliver(&[(true, &client_hello_record(head))])
            .client_hello
            .unwrap();
        assert!(ch.extension_list.is_empty());
        assert_eq!(ch.cipher_suites.len(), 16);
    }
}
