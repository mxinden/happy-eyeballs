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
//! let mut he = HappyEyeballs::new("example.com".to_string(), 443);
//! let now = Instant::now();
//!
//! // Process until we get outputs or timers
//! loop {
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
pub const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

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

    /// Connection attempt result
    ConnectionResult {
        address: SocketAddr,
        result: Result<(), String>,
        // TODO: When attempting a connection with ECH, the remote might send a
        // new ECH config to us on failure. That might be carried in this event?
    },

    /// IPv4 address needs NAT64 synthesis
    SynthesizeNat64 { ipv4_address: Ipv4Addr },

    /// Cancel the current connection attempt
    Cancel,
    // TODO: Do we need a TimerFired event? Isn't passing in an Option::None enough?

    // TODO: Should we have a GiveUp event? That way we could conclude our
    // logging, maybe log a summary. Maybe finish the Firefox Profiler Flow with
    // a final marker.
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsResponse {
    Https(DnsHttpsResponse),
    Aaaa(DnsAaaaResponse),
    A(DnsAResponse),
}

// TODO: Needs to contain the domain. E.g. HTTPS records can point to different domains.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsHttpsResponse {
    // TODO: It could have multiple entries, not just one ServiceInfo. See e.g.
    // facebook.com.
    //
    // TODO: This needs a domain, such that we can match this response to the
    // request that we previously sent.
    Positive {
        service_info: Vec<ServiceInfo>,
    },
    Negative,
}

// TODO: Needs to contain the domain. E.g. HTTPS records can point to different domains, which can trigger multiple AAAA queries.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsAaaaResponse {
    Positive { addresses: Vec<Ipv6Addr> },
    Negative,
}

// TODO: Needs to contain the domain. E.g. HTTPS records can point to different domains, which can trigger multiple A queries.
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

    /// Attempt to connect to an address
    AttemptConnection {
        address: SocketAddr,
        // TODO: Protocol
        // TODO: ECH
    },

    // TODO: Consider a CancelSendDnsQuery.
    /// Cancel a connection attempt
    CancelConnection(SocketAddr),
    // TODO: Should there be an event for giving up?
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

// TODO: We need to track what HTTP versions are supported, e.g. whether HTTP/3
// is disabled via pref or not. H1, H2, H3.
//
// TODO: We need to track whether HTTP RR DNS is enabled or disabled.
//
// TODO: We need to track whether ECH is enabled or disabled.
//
// TODO: Should we make HappyEyeballs proxy aware? E.g. should it know that the
// proxy is resolving the domain? Should it still trigger an HTTP RR lookup to
// see whether the remote supports HTTP/3? Should it first do MASQUE connect-udp
// and HTTP/3 and then HTTP CONNECT with HTTP/2?
//
// TODO: Should we make HappyEyeballs aware of whether this is a WebSocket
// connection? That way we could e.g. track EXTENDED CONNECT support, or
// fallback to a different connection in case WebSocket doesn't work? Likely for
// v2 of the project.
//
// TODO: Should we make HappyEyeballs aware of whether this is a WebTransport
// connection? That way we could e.g. track EXTENDED CONNECT support, or
// fallback to a different connection in case WebTransport doesn't work? Likely
// for v2 of the project.
//
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
    pub fn new(hostname: String, port: u16) -> Self {
        Self::with_network_config(hostname, port, NetworkConfig::default())
    }

    /// Create a new Happy Eyeballs state machine with custom network configuration
    pub fn with_network_config(hostname: String, port: u16, network_config: NetworkConfig) -> Self {
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
        if let Some(output) = self.connection_attempt_without_timeout() {
            return Some(output);
        }

        // Then try with timeout.
        if let Some(output) = self.connection_attempt_with_timeout(now) {
            return Some(output);
        }

        None
    }

    fn connection_attempt_without_timeout(&mut self) -> Option<Output> {
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

        return Some(Output::AttemptConnection { address });
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
                });
            }
            (_, ResolutionState::CompletedPositive { value: addresses }) => {
                let address = addresses[0];
                self.state = State::Connecting;
                return Some(Output::AttemptConnection {
                    address: SocketAddr::new(IpAddr::V4(address), self.target.1),
                });
            }
            _ => {}
        }

        return None;
    }
}
