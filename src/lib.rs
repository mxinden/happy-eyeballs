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
//!     match he.process(None) {
//!         Output::None => break,
//!         output => {
//!             // Handle the output (DNS query, connection attempt, etc.)
//!             println!("Output: {:?}", output);
//!         }
//!     }
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

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
        https_response: Option<Option<Option<()>>>,
        aaaa_response: Option<Option<Option<Vec<Ipv6Addr>>>>,
        a_response: Option<Option<Option<Vec<Ipv4Addr>>>>,
    },
    /// Attempting connections
    Connecting,
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
            state: State::Resolving {
                https_response: None,
                aaaa_response: None,
                a_response: None,
            },
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
        let output = self.send_dns_request();
        if output.is_some() {
            return output;
        }

        // Attempt connections.
        let output = self.connection_attempt();
        if output.is_some() {
            return output;
        }

        None
    }

    fn send_dns_request(&mut self) -> Option<Output> {
        match &mut self.state {
            State::Resolving {
                https_response,
                aaaa_response,
                a_response,
            } => {
                if https_response.is_none() {
                    *https_response = Some(None);
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::Https,
                    })
                } else if aaaa_response.is_none() {
                    *aaaa_response = Some(None);
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::Aaaa,
                    })
                } else if a_response.is_none() {
                    *a_response = Some(None);
                    Some(Output::SendDnsQuery {
                        hostname: self.target.0.clone(),
                        record_type: DnsRecordType::A,
                    })
                } else {
                    unreachable!("TODO improve");
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
                assert_eq!(*https_response, Some(None));
                match dns_https_response {
                    DnsHttpsResponse::Positive {
                        addresses: _,
                        service_info: _,
                    } => {
                        *https_response = Some(Some(Some(())));
                    }
                    DnsHttpsResponse::Negative => {
                        *https_response = Some(Some(None));
                    }
                }
            }
            DnsResponse::Aaaa(dns_aaaa_response) => {
                assert_eq!(*aaaa_response, Some(None));
                match dns_aaaa_response {
                    DnsAaaaResponse::Positive { addresses } => {
                        *aaaa_response = Some(Some(Some(addresses)));
                    }
                    DnsAaaaResponse::Negative => {
                        *aaaa_response = Some(Some(None));
                    }
                }
            }
            DnsResponse::A(dns_aresponse) => {
                assert_eq!(*a_response, Some(None));
                match dns_aresponse {
                    DnsAResponse::Positive { addresses } => {
                        *a_response = Some(Some(Some(addresses)));
                    }
                    DnsAResponse::Negative => {
                        *a_response = Some(Some(None));
                    }
                }
            }
        }

        None
    }

    fn connection_attempt(&mut self) -> Option<Output> {
        let State::Resolving {
            https_response,
            aaaa_response,
            a_response,
        } = &mut self.state
        else {
            return None;
        };

        todo!();
    }
}

// TODO: Given that this does not test the internals, should this be in tests/ instead of src/?
#[cfg(test)]
mod tests {
    use super::*;

    const HOSTNAME: &str = "example.com";
    const PORT: u16 = 443;
    const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    fn setup() -> (Instant, HappyEyeballs) {
        let now = Instant::now();
        let he = HappyEyeballs::new(HOSTNAME.to_string(), PORT, now);
        (now, he)
    }

    #[test]
    fn initial_state() {
        let (now, mut he) = setup();

        // Should immediately start with DNS query.
        match he.process(None, now) {
            Some(Output::SendDnsQuery {
                hostname,
                record_type,
            }) => {
                assert_eq!(hostname, "example.com");
                assert_eq!(record_type, DnsRecordType::Https);
            }
            _ => panic!("Expected SendDnsQuery output"),
        }
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

            match he.process(None, now) {
                Some(Output::SendDnsQuery {
                    hostname,
                    record_type,
                }) => {
                    assert_eq!(hostname, HOSTNAME);
                    assert_eq!(record_type, DnsRecordType::Https);
                }
                _ => panic!("Expected HTTPS query initially"),
            }

            match he.process(None, now) {
                Some(Output::SendDnsQuery {
                    hostname,
                    record_type,
                }) => {
                    assert_eq!(hostname, HOSTNAME);
                    assert_eq!(record_type, DnsRecordType::Aaaa);
                }
                _ => panic!(),
            }

            match he.process(None, now) {
                Some(Output::SendDnsQuery {
                    hostname,
                    record_type,
                }) => {
                    assert_eq!(hostname, HOSTNAME);
                    assert_eq!(record_type, DnsRecordType::A);
                }
                _ => panic!(),
            }
        }

        /// > Implementations SHOULD NOT wait for all answers to return before
        /// > starting the next steps of connection establishment.
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        #[test]
        fn dont_wait_for_all_dns_answers() {
            let (now, mut he) = setup();

            // Send all DNS queries.
            for _ in 0..3 {
                he.process(None, now);
            }

            assert_eq!(
                he.process(
                    Some(Input::DnsResponse(DnsResponse::Https(
                        DnsHttpsResponse::Positive {
                            addresses: vec![],
                            service_info: None
                        }
                    ))),
                    now
                ),
                None
            );

            assert_eq!(
                he.process(
                    Some(Input::DnsResponse(DnsResponse::Aaaa(
                        DnsAaaaResponse::Positive {
                            addresses: vec![V6_ADDR]
                        }
                    ))),
                    now
                ),
                Some(Output::AttemptConnection {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    protocol_info: None,
                })
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
        #[ignore]
        fn move_on_non_timeout() {
            let (now, mut he) = setup();

            // Send all DNS queries.
            for _ in 0..3 {
                he.process(None, now);
            }

            todo!();
        }

        /// > Or:
        /// >
        /// > - Some positive (non-empty) address answers have been received AND
        /// > - A resolution time delay has passed after which other answers have not been received
        ///
        /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        #[test]
        #[ignore]
        fn move_on_timeout() {
            let (now, mut he) = setup();
            todo!()
        }
    }
}
