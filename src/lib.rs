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

/// Resolution Delay - time to wait for AAAA after receiving A record
pub const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// Connection Attempt Delay - time between connection attempts
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Minimum Connection Attempt Delay (must be >= 10ms)
pub const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(100);

/// Maximum Connection Attempt Delay
pub const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);

/// Last Resort Local Synthesis Delay
pub const LAST_RESORT_SYNTHESIS_DELAY: Duration = Duration::from_secs(2);

/// Preferred Address Family Count
pub const PREFERRED_ADDRESS_FAMILY_COUNT: usize = 1;

/// Input events to the Happy Eyeballs state machine
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// DNS query result received
    DnsResult(DnsResult),

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
pub enum DnsResult {
    Https {
        addresses: Vec<IpAddr>,
        service_info: Option<ServiceInfo>,
    },
    Aaaa {
        addresses: Vec<Ipv6Addr>,
    },
    A {
        addresses: Vec<Ipv4Addr>,
    },
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
    Resolving(ResolvingState),
    /// Attempting connections
    Connecting,
}

#[derive(Debug, Clone, PartialEq)]
enum ResolvingState {
    Initial,
    Https {
        https_response: Option<()>,
    },
    Aaaa {
        https_response: Option<()>,
        aaaa_response: Option<Vec<Ipv6Addr>>,
    },
    A {
        https_response: Option<()>,
        aaaa_response: Option<Vec<Ipv6Addr>>,
        a_response: Option<Vec<Ipv4Addr>>,
    },
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
            state: State::Resolving(ResolvingState::Initial),
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
    pub fn process(&mut self, input: Option<Input>) -> Option<Output> {
        match (&mut self.state, input) {
            (State::Resolving(ResolvingState::Initial), None) => {
                self.state = State::Resolving(ResolvingState::Https {
                    https_response: None,
                });

                return Some(Output::SendDnsQuery {
                    hostname: self.target.0.clone(),
                    record_type: DnsRecordType::Https,
                });
            }
            (State::Resolving(ResolvingState::Https { https_response }), None) => {
                self.state = State::Resolving(ResolvingState::Aaaa {
                    // TODO: Not ideal. Can we do better?
                    https_response: https_response.take(),
                    aaaa_response: None,
                });

                return Some(Output::SendDnsQuery {
                    hostname: self.target.0.clone(),
                    record_type: DnsRecordType::Aaaa,
                });
            }
            (
                State::Resolving(ResolvingState::Aaaa {
                    https_response,
                    aaaa_response,
                }),
                None,
            ) => {
                self.state = State::Resolving(ResolvingState::A {
                    // TODO: Not ideal. Can we do better?
                    https_response: https_response.take(),
                    aaaa_response: aaaa_response.take(),
                    a_response: None,
                });

                return Some(Output::SendDnsQuery {
                    hostname: self.target.0.clone(),
                    record_type: DnsRecordType::A,
                });
            }
            (State::Resolving(resolving_state), Some(input)) => {
                match (&mut *resolving_state, input) {
                    (ResolvingState::Initial, _) => unreachable!(),
                    (
                        ResolvingState::Https { https_response }
                        | ResolvingState::Aaaa { https_response, .. }
                        | ResolvingState::A { https_response, .. },
                        Input::DnsResult(DnsResult::Https { .. }),
                    ) => {
                        *https_response = Some(());
                    }
                    (
                        ResolvingState::Aaaa { aaaa_response, .. }
                        | ResolvingState::A { aaaa_response, .. },
                        Input::DnsResult(DnsResult::Aaaa { addresses }),
                    ) => {
                        *aaaa_response = Some(addresses);
                    }
                    _ => todo!(),
                };

                match resolving_state {
                    ResolvingState::Aaaa {
                        https_response: Some(_),
                        aaaa_response: Some(_),
                    }
                    | ResolvingState::A {
                        https_response: Some(_),
                        aaaa_response: Some(_),
                        ..
                    } => {
                        return self.sorting();
                    }
                    _ => {}
                }
            }

            _ => todo!(),
        }

        return None;
    }

    fn sorting(&mut self) -> Option<Output> {
        let addresses = match std::mem::replace(&mut self.state, State::Connecting) {
            State::Resolving(
                ResolvingState::Aaaa { aaaa_response, .. }
                | ResolvingState::A { aaaa_response, .. },
            ) => aaaa_response.unwrap(),
            _ => todo!(),
        };
        Some(Output::AttemptConnection {
            address: SocketAddr::new(
                IpAddr::V6(addresses.into_iter().next().unwrap()),
                self.target.1,
            ),
            protocol_info: None,
        })
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

        // Process without input should start the connection process
        let output = he.process(None);

        // Should immediately start with DNS query
        match output {
            Some(Output::SendDnsQuery {
                hostname,
                record_type,
            }) => {
                assert_eq!(hostname, "example.com");
                assert_eq!(record_type, DnsRecordType::Https);
            }
            _ => panic!("Expected SendDnsQuery output, got: {:?}", output),
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

            match he.process(None) {
                Some(Output::SendDnsQuery {
                    hostname,
                    record_type,
                }) => {
                    assert_eq!(hostname, HOSTNAME);
                    assert_eq!(record_type, DnsRecordType::Https);
                }
                _ => panic!("Expected HTTPS query initially"),
            }

            match he.process(None) {
                Some(Output::SendDnsQuery {
                    hostname,
                    record_type,
                }) => {
                    assert_eq!(hostname, HOSTNAME);
                    assert_eq!(record_type, DnsRecordType::Aaaa);
                }
                _ => panic!(),
            }

            match he.process(None) {
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

            for _ in 0..3 {
                he.process(None); // Send all DNS queries
            }

            assert_eq!(
                he.process(Some(Input::DnsResult(DnsResult::Https {
                    addresses: vec![],
                    service_info: None,
                }))),
                None
            );

            assert_eq!(
                he.process(Some(Input::DnsResult(DnsResult::Aaaa {
                    addresses: vec![V6_ADDR],
                }))),
                Some(Output::AttemptConnection {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    protocol_info: None,
                })
            );
        }

        /// > The client moves onto sorting addresses and establishing
        /// > connections once one of the following condition sets is met:Either:
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
            todo!()
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
