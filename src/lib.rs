//! # Happy Eyeballs v3 Implementation
//!
//! WORK IN PROGRESS
//!
//! This crate provides a pure state machine implementation of Happy Eyeballs v3
//! as specified in [draft-ietf-happy-happyeyeballs-v3-02](https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html).
//!
//! Happy Eyeballs v3 is an algorithm for improving the performance of dual-stack
//! applications by racing IPv4 and IPv6 connections while optimizing for modern
//! network conditions including HTTPS service discovery and QUIC.
//!
//! ## Usage
//!
//! ```rust
//! use happy_eyeballs::*;
//! use std::time::Instant;
//!
//! let start_time = Instant::now();
//! let mut he = HappyEyeballs::new("example.com".to_string(), 443, start_time);
//!
//! // Process until we get outputs or timers
//! loop {
//!     let now = Instant::now();
//!     match he.process(None, now) {
//!         None => break,
//!         Some(output) => {
//!             // Handle the output (DNS query, connection attempt, etc.)
//!             println!("Output: {:?}", output);
//!         }
//!     }
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// > The RECOMMENDED value for the Resolution Delay is 50 milliseconds.
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// Input events to the Happy Eyeballs state machine
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// DNS query result received
    DnsResponse(DnsResponse),

    /// DNS query failed
    DnsError {
        record_type: DnsRecordType,
        error: String,
    },

    /// Timer expired (for various delays)
    Timer {
        timer_type: TimerType,
        current_time: Instant,
    },

    /// Connection attempt result
    ConnectionResult {
        address: SocketAddr,
        result: Result<(), String>,
        current_time: Instant,
    },

    /// IPv4 address needs NAT64 synthesis
    SynthesizeNat64 { ipv4_address: Ipv4Addr },

    /// Cancel the current connection attempt
    Cancel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsResponse {
    Https(DnsHttpsResponse),
    Aaaa(DnsAaaaResponse),
    A(DnsAResponse),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsHttpsResponse {
    Positive {
        addresses: Vec<IpAddr>,
        service_info: Option<ServiceInfo>,
    },
    Negative,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsAaaaResponse {
    Positive { addresses: Vec<Ipv6Addr> },
    Negative,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsAResponse {
    Positive { addresses: Vec<Ipv4Addr> },
    Negative,
}

/// Output events from the Happy Eyeballs state machine
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// Send a DNS query
    SendDnsQuery {
        hostname: String,
        record_type: DnsRecordType,
    },

    /// Start a timer
    StartTimer {
        timer_type: TimerType,
        duration: Duration,
    },

    /// Cancel a timer
    CancelTimer(TimerType),

    /// Attempt to connect to an address
    AttemptConnection {
        address: SocketAddr,
        protocol_info: Option<ProtocolInfo>,
    },

    /// Cancel a connection attempt
    CancelConnection(SocketAddr),

    /// Connection successfully established
    ConnectionEstablished {
        address: SocketAddr,
        protocol_info: Option<ProtocolInfo>,
    },

    /// All connection attempts failed
    ConnectionFailed { error: String },
}

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    Https,
    Aaaa,
    A,
}

/// Timer types for different delays
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    /// Resolution Delay (50ms recommended)
    ResolutionDelay,
    /// Connection Attempt Delay (250ms recommended)
    ConnectionAttemptDelay,
    /// Last Resort Local Synthesis Delay (2s recommended)
    LastResortSynthesis,
}

/// Service information from HTTPS records
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceInfo {
    pub priority: u16,
    pub target_name: String,
    pub alpn_protocols: Vec<String>,
    pub ech_config: Option<Vec<u8>>,
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
}

/// Protocol information for connections
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolInfo {
    pub alpn: Option<String>,
    pub supports_ech: bool,
    pub service_priority: Option<u16>,
}

/// State of the Happy Eyeballs algorithm
#[derive(Debug, Clone, PartialEq)]
enum State {
    /// Performing DNS resolution
    Resolving {
        // TODO: Option<Option<Option<_>>> isn't ideal. Refactor?
        https_response: ResolutionState<()>,
        aaaa_response: ResolutionState<Vec<Ipv6Addr>>,
        a_response: ResolutionState<Vec<Ipv4Addr>>,
    },
    /// Attempting connections
    Connecting,
}

impl Default for State {
    fn default() -> Self {
        State::Resolving {
            https_response: ResolutionState::NotStarted,
            aaaa_response: ResolutionState::NotStarted,
            a_response: ResolutionState::NotStarted,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ResolutionState<V> {
    NotStarted,
    InProgress { started: Instant },
    // TODO: Consider nesting the two Completed* states.
    CompletedPositive { value: V },
    CompletedNegative,
}

/// Network configuration for Happy Eyeballs behavior
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkConfig {
    /// Dual-stack network with IPv4 and IPv6 available
    DualStack {
        /// Whether to prefer IPv6 over IPv4
        prefer_ipv6: bool,
    },
    /// IPv6-only network requiring NAT64 for IPv4 connectivity
    Ipv6Only {
        /// NAT64 prefix for address synthesis
        nat64_prefix: Option<Ipv6Addr>,
    },
    /// IPv4-only network
    Ipv4Only,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig::DualStack { prefer_ipv6: true }
    }
}

impl NetworkConfig {
    fn v6(&self) -> bool {
        match self {
            NetworkConfig::DualStack { prefer_ipv6 } => *prefer_ipv6,
            NetworkConfig::Ipv6Only { .. } => true,
            NetworkConfig::Ipv4Only => false,
        }
    }
}

/// Happy Eyeballs v3 state machine
pub struct HappyEyeballs {
    /// Current state of the state machine
    state: State,
    /// Network configuration
    network_config: NetworkConfig,
    // TODO: Split in host and port?
    /// Target hostname and port
    target: (String, u16),
}

impl HappyEyeballs {
    /// Create a new Happy Eyeballs state machine with default network config
    pub fn new(hostname: String, port: u16, start_time: Instant) -> Self {
        Self::with_network_config(hostname, port, start_time, NetworkConfig::default())
    }

    /// Create a new Happy Eyeballs state machine with custom network configuration
    pub fn with_network_config(
        hostname: String,
        port: u16,
        start_time: Instant,
        network_config: NetworkConfig,
    ) -> Self {
        Self {
            state: State::default(),
            network_config,
            target: (hostname, port),
        }
    }

    /// Process an input event and return the corresponding output
    ///
    /// Call with `None` to advance the state machine and get any pending outputs.
    /// Call with `Some(input)` to provide external input (DNS results, timers, etc.).
    ///
    /// The caller should keep calling `process(None)` until it returns `Output::None`
    /// or a timer output, then wait for the corresponding input before continuing.
    pub fn process(&mut self, input: Option<Input>, now: Instant) -> Option<Output> {
        // Handle input.
        let output = match (&mut self.state, input) {
            (State::Resolving { .. }, Some(Input::DnsResponse(response))) => {
                self.on_dns_response(response)
            }
            _ => None,
        };
        if output.is_some() {
            return output;
        }

        // Send DNS queries.
        let output = self.send_dns_request(now);
        if output.is_some() {
            return output;
        }

        // Attempt connections.
        let output = self.connection_attempt(now);
        if output.is_some() {
            return output;
        }

        None
    }

    fn send_dns_request(&mut self, now: Instant) -> Option<Output> {
        match &mut self.state {
            State::Resolving {
                https_response,
                aaaa_response,
                a_response,
            } => {
                if matches!(https_response, ResolutionState::NotStarted) {
                    *https_response = ResolutionState::InProgress { started: now };
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::Https,
                    })
                } else if matches!(aaaa_response, ResolutionState::NotStarted) {
                    *aaaa_response = ResolutionState::InProgress { started: now };
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::Aaaa,
                    })
                } else if matches!(a_response, ResolutionState::NotStarted) {
                    *a_response = ResolutionState::InProgress { started: now };
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::A,
                    })
                } else {
                    None
                }
            }
            State::Connecting => None,
        }
    }

    fn on_dns_response(&mut self, response: DnsResponse) -> Option<Output> {
        let State::Resolving {
            https_response,
            aaaa_response,
            a_response,
        } = &mut self.state
        else {
            unreachable!();
        };

        match response {
            DnsResponse::Https(dns_https_response) => {
                assert!(matches!(
                    *https_response,
                    ResolutionState::InProgress { started: _ }
                ));
                match dns_https_response {
                    DnsHttpsResponse::Positive {
                        addresses: _,
                        service_info: _,
                    } => {
                        *https_response = ResolutionState::CompletedPositive { value: () };
                    }
                    DnsHttpsResponse::Negative => {
                        *https_response = ResolutionState::CompletedNegative;
                    }
                }
            }
            DnsResponse::Aaaa(dns_aaaa_response) => {
                assert!(matches!(
                    *aaaa_response,
                    ResolutionState::InProgress { started: _ }
                ));
                match dns_aaaa_response {
                    DnsAaaaResponse::Positive { addresses } => {
                        *aaaa_response = ResolutionState::CompletedPositive { value: addresses };
                    }
                    DnsAaaaResponse::Negative => {
                        *aaaa_response = ResolutionState::CompletedNegative;
                    }
                }
            }
            DnsResponse::A(dns_aresponse) => {
                assert!(matches!(
                    *a_response,
                    ResolutionState::InProgress { started: _ }
                ));
                match dns_aresponse {
                    DnsAResponse::Positive { addresses } => {
                        *a_response = ResolutionState::CompletedPositive { value: addresses };
                    }
                    DnsAResponse::Negative => {
                        *a_response = ResolutionState::CompletedNegative;
                    }
                }
            }
        }

        None
    }

    /// > The client moves onto sorting addresses and establishing connections
    /// once one of the following condition sets is met:
    /// >
    /// > Either:
    /// >  
    /// > - Some positive (non-empty) address answers have been received AND
    /// > - A postive (non-empty) or negative (empty) answer has been received for the preferred address family that was queried AND
    /// > - SVCB/HTTPS service information has been received (or has received a negative response)
    /// >
    /// > Or:
    /// > - ome positive (non-empty) address answers have been received AND
    /// > - A resolution time delay has passed after which other answers have not been received
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
    fn connection_attempt(&mut self, now: Instant) -> Option<Output> {
        // First try without timeout.
        if let Some(output) = self.connection_attempt_without_timeout(now) {
            return Some(output);
        }

        // Then try with timeout.
        if let Some(output) = self.connection_attempt_with_timeout(now) {
            return Some(output);
        }

        None
    }

    fn connection_attempt_without_timeout(&mut self, now: Instant) -> Option<Output> {
        let State::Resolving {
            https_response,
            aaaa_response,
            a_response,
        } = &self.state
        else {
            return None;
        };

        // > Some positive (non-empty) address answers have been received AND
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        match (&aaaa_response, &a_response) {
            (ResolutionState::CompletedPositive { .. }, _)
            | (_, ResolutionState::CompletedPositive { .. }) => {}
            _ => return None,
        }

        // > A postive (non-empty) or negative (empty) answer has been received for the preferred address family that was queried AND
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        match (&self.network_config, &aaaa_response, &a_response) {
            (
                NetworkConfig::Ipv4Only,
                _,
                ResolutionState::CompletedPositive { .. } | ResolutionState::CompletedNegative,
            ) => {}
            (
                NetworkConfig::Ipv6Only { .. },
                ResolutionState::CompletedPositive { .. } | ResolutionState::CompletedNegative,
                _,
            ) => {}
            (
                NetworkConfig::DualStack { prefer_ipv6: false },
                _,
                ResolutionState::CompletedPositive { .. } | ResolutionState::CompletedNegative,
            ) => {}
            (
                NetworkConfig::DualStack { prefer_ipv6: true },
                ResolutionState::CompletedPositive { .. } | ResolutionState::CompletedNegative,
                _,
            ) => {}
            _ => return None,
        }

        // > SVCB/HTTPS service information has been received (or has received a negative response)
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        if !matches!(
            https_response,
            ResolutionState::CompletedPositive { .. } | ResolutionState::CompletedNegative
        ) {
            return None;
        }

        let use_v6 = match self.network_config {
            NetworkConfig::DualStack { prefer_ipv6 } => prefer_ipv6,
            NetworkConfig::Ipv6Only { .. } => true,
            NetworkConfig::Ipv4Only => false,
        };

        let address = match (use_v6, &aaaa_response, &a_response) {
            (true, ResolutionState::CompletedPositive { value: addresses }, _) => {
                SocketAddr::new(IpAddr::V6(addresses[0]), self.target.1)
            }
            (true, _, ResolutionState::CompletedPositive { value: addresses }) => {
                SocketAddr::new(IpAddr::V4(addresses[0]), self.target.1)
            }
            (false, _, ResolutionState::CompletedPositive { value: addresses }) => {
                SocketAddr::new(IpAddr::V4(addresses[0]), self.target.1)
            }
            (false, ResolutionState::CompletedPositive { value: addresses }, _) => {
                SocketAddr::new(IpAddr::V6(addresses[0]), self.target.1)
            }
            _ => return None,
        };

        self.state = State::Connecting;

        return Some(Output::AttemptConnection {
            address,
            protocol_info: None,
        });
    }

    fn connection_attempt_with_timeout(&mut self, now: Instant) -> Option<Output> {
        let State::Resolving {
            https_response,
            aaaa_response,
            a_response,
        } = &self.state
        else {
            return None;
        };

        // > Or:
        // >
        // > - Some positive (non-empty) address answers have been received AND
        // > - A resolution time delay has passed after which other answers have not been received
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        match https_response {
            ResolutionState::InProgress { started }
                if now.duration_since(*started) >= RESOLUTION_DELAY => {}
            _ => return None,
        }
        match (aaaa_response, a_response) {
            (ResolutionState::InProgress { started }, _)
                if now.duration_since(*started) >= RESOLUTION_DELAY => {}
            (_, ResolutionState::InProgress { started })
                if now.duration_since(*started) >= RESOLUTION_DELAY => {}
            _ => return None,
        }
        match (aaaa_response, a_response) {
            (ResolutionState::CompletedPositive { value: addresses }, _) => {
                let address = addresses[0];
                self.state = State::Connecting;
                return Some(Output::AttemptConnection {
                    address: SocketAddr::new(IpAddr::V6(address), self.target.1),
                    protocol_info: None,
                });
            }
            (_, ResolutionState::CompletedPositive { value: addresses }) => {
                let address = addresses[0];
                self.state = State::Connecting;
                return Some(Output::AttemptConnection {
                    address: SocketAddr::new(IpAddr::V4(address), self.target.1),
                    protocol_info: None,
                });
            }
            _ => {}
        }

        return None;
    }
}

// TODO: Given that this does not test the internals, should this be in tests/ instead of src/?
#[cfg(test)]
mod tests {
    use super::*;

    const HOSTNAME: &str = "example.com";
    const PORT: u16 = 443;
    const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    trait HappyEyeballsExt {
        fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant);
    }

    impl HappyEyeballsExt for HappyEyeballs {
        fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant) {
            for (input, expected_output) in input_output {
                let output = self.process(input, now);
                assert_eq!(output, expected_output);
            }
        }
    }

    fn out_send_dns_https() -> Output {
        Output::SendDnsQuery {
            hostname: HOSTNAME.to_string(),
            record_type: DnsRecordType::Https,
        }
    }

    fn out_send_dns_aaaa() -> Output {
        Output::SendDnsQuery {
            hostname: HOSTNAME.to_string(),
            record_type: DnsRecordType::Aaaa,
        }
    }

    fn out_send_dns_a() -> Output {
        Output::SendDnsQuery {
            hostname: HOSTNAME.to_string(),
            record_type: DnsRecordType::A,
        }
    }

    fn out_attempt_v6() -> Output {
        Output::AttemptConnection {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            protocol_info: None,
        }
    }

    fn out_attempt_v4() -> Output {
        Output::AttemptConnection {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            protocol_info: None,
        }
    }

    fn in_dns_https_positive() -> Input {
        Input::DnsResponse(DnsResponse::Https(DnsHttpsResponse::Positive {
            addresses: vec![],
            service_info: None,
        }))
    }

    fn in_dns_aaaa_positive() -> Input {
        Input::DnsResponse(DnsResponse::Aaaa(DnsAaaaResponse::Positive {
            addresses: vec![V6_ADDR],
        }))
    }

    fn in_dns_a_positive() -> Input {
        Input::DnsResponse(DnsResponse::A(DnsAResponse::Positive {
            addresses: vec![V4_ADDR],
        }))
    }

    fn setup() -> (Instant, HappyEyeballs) {
        setup_with_config(NetworkConfig::default())
    }

    fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
        let now = Instant::now();
        let he = HappyEyeballs::with_network_config(HOSTNAME.to_string(), PORT, now, config);
        (now, he)
    }

    #[test]
    fn initial_state() {
        let (now, mut he) = setup();

        he.expect(vec![(None, Some(out_send_dns_https()))], now);
    }

    /// > 4. Hostname Resolution
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4>
    #[cfg(test)]
    mod section_4_hostname_resolution {
        use super::*;

        /// > All of the DNS queries SHOULD be made as soon after one another as
        /// > possible. The order in which the queries are sent SHOULD be as follows
        /// > (omitting any query that doesn't apply based on the logic described
        /// > above):
        /// >
        /// > 1. SVCB or HTTPS query
        /// > 2. AAAA query
        /// > 3. A query
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.1>
        #[test]
        fn sendig_dns_queries() {
            let (now, mut he) = setup();

            he.expect(
                vec![
                    (None, Some(out_send_dns_https())),
                    (None, Some(out_send_dns_aaaa())),
                    (None, Some(out_send_dns_a())),
                ],
                now,
            );
        }

        /// > Implementations SHOULD NOT wait for all answers to return before
        /// > starting the next steps of connection establishment.
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        #[test]
        fn dont_wait_for_all_dns_answers() {
            let (now, mut he) = setup();

            he.expect(
                vec![
                    (None, Some(out_send_dns_https())),
                    (None, Some(out_send_dns_aaaa())),
                    (None, Some(out_send_dns_a())),
                    (Some(in_dns_https_positive()), None),
                    (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
                ],
                now,
            );
        }

        /// > The client moves onto sorting addresses and establishing
        /// > connections once one of the following condition sets is met:
        /// >
        /// > Either:
        /// >
        /// > - Some positive (non-empty) address answers have been received AND
        /// > - A postive (non-empty) or negative (empty) answer has been
        ///     received for the preferred address family that was queried AND
        /// > - SVCB/HTTPS service information has been received (or has received a negative response)
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        #[test]
        fn move_on_non_timeout() {
            #[derive(Debug)]
            struct Case {
                address_family: NetworkConfig,
                positive: DnsResponse,
                preferred: Option<DnsResponse>,
                https: DnsResponse,
                expected: Option<Output>,
            }

            let test_cases = vec![
                // V6 preferred, V6 positive, HTTPS positive, expect V6 connection attempt
                Case {
                    address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                    positive: DnsResponse::Aaaa(DnsAaaaResponse::Positive {
                        addresses: vec![V6_ADDR],
                    }),
                    preferred: None,
                    https: DnsResponse::Https(DnsHttpsResponse::Positive {
                        addresses: vec![],
                        service_info: None,
                    }),
                    expected: Some(Output::AttemptConnection {
                        address: SocketAddr::new(V6_ADDR.into(), PORT),
                        protocol_info: None,
                    }),
                },
                // V6 preferred, V4 positive, V6 positive, HTTPS positive, expect V6 connection attempt
                Case {
                    address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                    positive: DnsResponse::A(DnsAResponse::Positive {
                        addresses: vec![V4_ADDR],
                    }),
                    preferred: Some(DnsResponse::Aaaa(DnsAaaaResponse::Positive {
                        addresses: vec![V6_ADDR],
                    })),
                    https: DnsResponse::Https(DnsHttpsResponse::Positive {
                        addresses: vec![],
                        service_info: None,
                    }),
                    expected: Some(Output::AttemptConnection {
                        address: SocketAddr::new(V6_ADDR.into(), PORT),
                        protocol_info: None,
                    }),
                },
                // V6 preferred, V6 negative, V4 positive, HTTPS positive, expect V4 connection attempt
                Case {
                    address_family: NetworkConfig::DualStack { prefer_ipv6: true },
                    positive: DnsResponse::A(DnsAResponse::Positive {
                        addresses: vec![V4_ADDR],
                    }),
                    preferred: Some(DnsResponse::Aaaa(DnsAaaaResponse::Negative)),
                    https: DnsResponse::Https(DnsHttpsResponse::Positive {
                        addresses: vec![],
                        service_info: None,
                    }),
                    expected: Some(Output::AttemptConnection {
                        address: SocketAddr::new(V4_ADDR.into(), PORT),
                        protocol_info: None,
                    }),
                },
                // TODO: V4
            ];

            for test_case in test_cases {
                let Case {
                    address_family: _,
                    positive,
                    preferred,
                    https,
                    expected: _,
                } = test_case;

                let (now, mut he) = setup_with_config(test_case.address_family);

                // Send all DNS queries.
                for _ in 0..3 {
                    he.process(None, now);
                }

                he.process(Some(Input::DnsResponse(positive)), now);
                if let Some(preferred) = preferred {
                    he.process(Some(Input::DnsResponse(preferred)), now);
                }
                let out = he.process(Some(Input::DnsResponse(https)), now);
                assert_eq!(out, test_case.expected);
            }
        }

        /// > Or:
        /// >
        /// > - Some positive (non-empty) address answers have been received AND
        /// > - A resolution time delay has passed after which other answers have not been received
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        // TODO: Other combinations
        #[test]
        fn move_on_timeout() {
            let (mut now, mut he) = setup();

            he.expect(
                vec![
                    (None, Some(out_send_dns_https())),
                    (None, Some(out_send_dns_aaaa())),
                    (None, Some(out_send_dns_a())),
                    (Some(in_dns_a_positive()), None),
                ],
                now,
            );

            now += RESOLUTION_DELAY;

            he.expect(vec![(None, Some(out_attempt_v4()))], now);
        }

        /// > ServiceMode records can contain address hints via ipv6hint and
        /// > ipv4hint parameters. When these are received, they SHOULD be
        /// > considered as positive non-empty answers for the purpose of the
        /// > algorithm when A and AAAA records corresponding to the TargetName
        /// > are not available yet.
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
        #[test]
        #[ignore]
        fn https_hints() {
            todo!();
        }

        /// > Note that clients are still required to issue A and AAAA queries
        /// > for those TargetNames if they haven't yet received those records.
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
        #[test]
        #[ignore]
        fn https_hints_still_query_a_aaaa() {
            todo!();
        }
    }
}
