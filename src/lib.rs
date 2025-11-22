//! # Happy Eyeballs v3 Implementation
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

/// Connection attempt state
#[derive(Debug, Clone, PartialEq)]
struct ConnectionAttempt {
    address: SocketAddr,
    protocol_info: Option<ProtocolInfo>,
    started_at: Instant,
    in_progress: bool,
}

/// State of the Happy Eyeballs algorithm
#[derive(Debug, Clone, PartialEq)]
enum State {
    /// Performing DNS resolution
    Resolving(ResolvingState),
    /// Sorting resolved addresses according to preferences
    Sorting,
    /// Have some addresses, waiting for more or timeout
    WaitingForMoreAddresses,
    /// Attempting connections
    Connecting,
    /// Successfully connected
    Connected,
    /// Failed to connect
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
enum ResolvingState {
    Initial,
    Https {
        https_response: Option<()>,
    },
    Aaaa {
        https_response: Option<()>,
        aaa_response: Option<()>,
    },
    A {
        https_response: Option<()>,
        aaa_response: Option<()>,
        a_response: Option<()>,
    },
}

/// Resolved address with associated metadata
#[derive(Debug, Clone, PartialEq)]
struct ResolvedAddress {
    address: IpAddr,
    port: u16,
    service_info: Option<ServiceInfo>,
    /// Destination Address Selection preference order
    preference_order: usize,
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
    /// DNS queries that have been sent
    pending_dns_queries: std::collections::HashSet<DnsRecordType>,
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
            pending_dns_queries: std::collections::HashSet::new(),
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
        match (&self.state, input) {
            // Start input is now handled in advance_state_machine
            (State::Resolving(ResolvingState::Initial), None) => {
                assert!(
                    self.pending_dns_queries.is_empty(),
                    "No DNS queries should be pending when starting"
                );
                // Start with HTTPS query according to Section 4.1
                self.pending_dns_queries.insert(DnsRecordType::Https);

                self.state = State::Resolving(ResolvingState::Https {
                    https_response: None,
                });

                return Some(Output::SendDnsQuery {
                    hostname: self.target.0.clone(),
                    record_type: DnsRecordType::Https,
                });
            }
            _ => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let now = Instant::now();
        let mut he = HappyEyeballs::new("example.com".to_string(), 443, now);

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
        let now = Instant::now();
        let mut he = HappyEyeballs::new("example.com".to_string(), 443, now);

        match he.process(None) {
            Some(Output::SendDnsQuery {
                hostname,
                record_type,
            }) => {
                assert_eq!(hostname, "example.com");
                assert_eq!(record_type, DnsRecordType::Https);
            }
            _ => panic!("Expected HTTPS query initially"),
        }

        match he.process(None) {
            Some(Output::SendDnsQuery {
                hostname,
                record_type,
            }) => {
                assert_eq!(hostname, "example.com");
                assert_eq!(record_type, DnsRecordType::Aaaa);
            }
            _ => panic!(),
        }

        match he.process(None) {
            Some(Output::SendDnsQuery {
                hostname,
                record_type,
            }) => {
                assert_eq!(hostname, "example.com");
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
        let now = Instant::now();
        let mut he = HappyEyeballs::new("example.com".to_string(), 443, now);

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
                addresses: vec!["2001:db8::1".parse().unwrap()],
            }))),
            Some(Output::AttemptConnection {
                address: SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
                protocol_info: None,
            })
        );
    }
}
