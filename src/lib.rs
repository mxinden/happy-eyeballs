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

/// > Connection Attempt Delay (Section 6): The time to wait between connection
/// > attempts in the absence of RTT data. Recommended to be 250 milliseconds.
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-9>
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

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
pub struct DnsResponse {
    pub target_name: TargetName,
    pub inner: DnsResponseInner,
}

impl DnsResponse {
    fn record_type(&self) -> DnsRecordType {
        self.inner.record_type()
    }

    fn positive(&self) -> bool {
        self.inner.positive()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsResponseInner {
    Https(Result<Vec<ServiceInfo>, ()>),
    Aaaa(Result<Vec<Ipv6Addr>, ()>),
    A(Result<Vec<Ipv4Addr>, ()>),
}

impl DnsResponseInner {
    fn record_type(&self) -> DnsRecordType {
        match self {
            DnsResponseInner::Https(_) => DnsRecordType::Https,
            DnsResponseInner::Aaaa(_) => DnsRecordType::Aaaa,
            DnsResponseInner::A(_) => DnsRecordType::A,
        }
    }

    fn positive(&self) -> bool {
        match self {
            DnsResponseInner::Https(r) => r.is_ok(),
            DnsResponseInner::Aaaa(r) => r.is_ok(),
            DnsResponseInner::A(r) => r.is_ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetName(String);

impl From<&str> for TargetName {
    fn from(s: &str) -> Self {
        TargetName(s.to_string())
    }
}

/// Output events from the Happy Eyeballs state machine
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// Send a DNS query
    SendDnsQuery {
        hostname: TargetName,
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
    pub target_name: TargetName,
    pub alpn_protocols: Vec<String>,
    pub ech_config: Option<Vec<u8>>,
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq)]
enum DnsQuery {
    InProgress {
        started: Instant,
        target_name: TargetName,
        record_type: DnsRecordType,
    },
    Completed {
        response: DnsResponse,
    },
}

impl DnsQuery {
    fn record_type(&self) -> DnsRecordType {
        match self {
            DnsQuery::InProgress { record_type, .. } => *record_type,
            DnsQuery::Completed { response } => match response.inner {
                DnsResponseInner::Https(_) => DnsRecordType::Https,
                DnsResponseInner::Aaaa(_) => DnsRecordType::Aaaa,
                DnsResponseInner::A(_) => DnsRecordType::A,
            },
        }
    }

    fn target_name(&self) -> &TargetName {
        match self {
            DnsQuery::InProgress { target_name, .. } => target_name,
            DnsQuery::Completed { response } => &response.target_name,
        }
    }

    fn positive(&self) -> bool {
        match self {
            DnsQuery::InProgress { .. } => false,
            DnsQuery::Completed { response } => response.positive(),
        }
    }

    fn get_response(&self) -> Option<&DnsResponse> {
        match self {
            DnsQuery::InProgress { .. } => None,
            DnsQuery::Completed { response } => Some(response),
        }
    }
}

/// Configuration for supported HTTP versions.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpVersions {
    /// Whether HTTP/1.1 is enabled.
    pub h1: bool,
    /// Whether HTTP/2 is enabled.
    pub h2: bool,
    /// Whether HTTP/3 is enabled.
    pub h3: bool,
}

impl Default for HttpVersions {
    fn default() -> Self {
        // Enable all by default.
        Self {
            h1: true,
            h2: true,
            h3: true,
        }
    }
}

/// IP connectivity and preference mode.
#[derive(Debug, Clone, PartialEq)]
pub enum IpPreference {
    /// Dual-stack available, prefer IPv6 over IPv4.
    DualStackPreferV6,
    /// Dual-stack available, prefer IPv4 over IPv6.
    DualStackPreferV4,
    /// IPv6-only network.
    Ipv6Only,
    /// IPv4-only network.
    Ipv4Only,
}

// TODO: Allow user to provide alt-svc information from previous connections.
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
pub struct NetworkConfig {
    /// Supported HTTP versions
    pub http_versions: HttpVersions,
    /// IP connectivity and preference
    pub ip: IpPreference,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            http_versions: HttpVersions::default(),
            ip: IpPreference::DualStackPreferV6,
        }
    }
}

impl NetworkConfig {
    fn prefer_v6(&self) -> bool {
        match self.ip {
            IpPreference::DualStackPreferV6 | IpPreference::Ipv6Only => true,
            IpPreference::DualStackPreferV4 | IpPreference::Ipv4Only => false,
        }
    }

    fn preferred_dns_record_type(&self) -> DnsRecordType {
        match self.ip {
            IpPreference::DualStackPreferV6 | IpPreference::Ipv6Only => DnsRecordType::Aaaa,
            IpPreference::DualStackPreferV4 | IpPreference::Ipv4Only => DnsRecordType::A,
        }
    }
}

/// Happy Eyeballs v3 state machine
pub struct HappyEyeballs {
    dns_queries: Vec<DnsQuery>,
    connection_attempts: Vec<(IpAddr, Instant)>,
    /// Network configuration
    network_config: NetworkConfig,
    // TODO: Split in host and port?
    /// Target hostname and port
    target: (TargetName, u16),
}

impl HappyEyeballs {
    /// Create a new Happy Eyeballs state machine with default network config
    pub fn new(hostname: String, port: u16) -> Self {
        Self::with_network_config(hostname, port, NetworkConfig::default())
    }

    /// Create a new Happy Eyeballs state machine with custom network configuration
    pub fn with_network_config(hostname: String, port: u16, network_config: NetworkConfig) -> Self {
        Self {
            network_config,
            dns_queries: Vec::new(),
            connection_attempts: Vec::new(),
            target: (TargetName(hostname), port),
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
        let output = match input {
            Some(Input::DnsResponse(response)) => self.on_dns_response(response),
            _ => None,
        };
        if output.is_some() {
            return output;
        }

        // TODO: Move below self.connection_attempt()?
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

        let output = self.send_dns_request_for_target_name(now);
        if output.is_some() {
            return output;
        }

        None
    }

    fn send_dns_request(&mut self, now: Instant) -> Option<Output> {
        for record_type in [DnsRecordType::Https, DnsRecordType::Aaaa, DnsRecordType::A] {
            if !self
                .dns_queries
                .iter()
                .any(|q| q.record_type() == record_type)
            {
                self.dns_queries.push(DnsQuery::InProgress {
                    started: now,
                    target_name: self.target.0.clone(),
                    record_type,
                });
                return Some(Output::SendDnsQuery {
                    hostname: self.target.0.clone(),
                    record_type,
                });
            }
        }

        None
    }

    /// > Note that clients are still required to issue A and AAAA queries
    /// > for those TargetNames if they haven't yet received those records.
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
    fn send_dns_request_for_target_name(&mut self, now: Instant) -> Option<Output> {
        // Check if we have HTTPS response with ServiceInfo
        let target_names = self
            .dns_queries
            .iter()
            .filter_map(|q| match q {
                DnsQuery::Completed {
                    response:
                        DnsResponse {
                            target_name: _,
                            inner: DnsResponseInner::Https(Ok(service_infos)),
                        },
                } => Some(service_infos.iter().map(|i| &i.target_name)),
                _ => None,
            })
            .flatten();

        for target_name in target_names {
            for record_type in [DnsRecordType::Aaaa, DnsRecordType::A] {
                if !self
                    .dns_queries
                    .iter()
                    .any(|q| q.target_name() == target_name && q.record_type() == record_type)
                {
                    let target_name = target_name.clone();

                    self.dns_queries.push(DnsQuery::InProgress {
                        started: now,
                        target_name: target_name.clone(),
                        record_type,
                    });
                    return Some(Output::SendDnsQuery {
                        hostname: target_name,
                        record_type,
                    });
                }
            }
        }

        None
    }

    fn on_dns_response(&mut self, response: DnsResponse) -> Option<Output> {
        let Some(query) = self
            .dns_queries
            .iter_mut()
            .filter(|q| *q.target_name() == response.target_name)
            .find(|q| q.record_type() == response.record_type())
        else {
            debug_assert!(false, "got {response:?} but never sent query");
            return None;
        };

        match &query {
            DnsQuery::InProgress { .. } => {}
            DnsQuery::Completed { response } => {
                debug_assert!(false, "got {response:?} for already responded {query:?}");
                return None;
            }
        }

        *query = DnsQuery::Completed { response };

        None
    }

    /// > The client moves onto sorting addresses and establishing connections
    /// > once one of the following condition sets is met:
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
        let mut move_on = false;
        move_on |= self.move_on_without_timeout();
        move_on |= self.move_on_with_timeout(now);
        if !move_on {
            return None;
        }

        if self
            .connection_attempts
            .iter()
            .any(|(_, t)| now.duration_since(*t) < CONNECTION_ATTEMPT_DELAY)
        {
            return None;
        }
        let mut ips = self
            .dns_queries
            .iter()
            .filter_map(|q| q.get_response())
            .filter_map(|r| match &r.inner {
                DnsResponseInner::Https(infos) => {
                    // > ServiceMode records can contain address hints via ipv6hint and
                    // > ipv4hint parameters. When these are received, they SHOULD be
                    // > considered as positive non-empty answers for the purpose of the
                    // > algorithm when A and AAAA records corresponding to the TargetName
                    // > are not available yet.
                    //
                    // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
                    let got_a = self
                        .dns_queries
                        .iter()
                        .filter(|q| *q.target_name() == self.target.0)
                        .any(|q| {
                            matches!(
                                q,
                                DnsQuery::Completed {
                                    response:
                                        DnsResponse {
                                            inner: DnsResponseInner::A(Ok(addrs)),
                                            ..
                                        },
                                } if !addrs.is_empty()
                            )
                        });
                    let got_aaaa = self
                        .dns_queries
                        .iter()
                        .filter(|q| *q.target_name() == self.target.0)
                        .any(|q| {
                            matches!(
                                q,
                                DnsQuery::Completed {
                                    response:
                                        DnsResponse {
                                            inner: DnsResponseInner::Aaaa(Ok(addrs)),
                                            ..
                                        },
                                } if !addrs.is_empty()
                            )
                        });
                    Some(
                        infos
                            .as_ref()
                            .ok()?
                            .iter()
                            .flat_map(|info| {
                                info.ipv6_hints
                                    .iter()
                                    .cloned()
                                    .map(IpAddr::V6)
                                    .chain(info.ipv4_hints.iter().cloned().map(IpAddr::V4))
                                    .filter(|ip| match ip {
                                        IpAddr::V6(_) => !got_aaaa,
                                        IpAddr::V4(_) => !got_a,
                                    })
                            })
                            .collect::<Vec<_>>()
                            .into_iter(),
                    )
                }
                DnsResponseInner::Aaaa(ipv6_addrs) => Some(
                    // TODO: Instead of cloned, can these be references?
                    ipv6_addrs
                        .as_ref()
                        .ok()?
                        .iter()
                        .cloned()
                        .map(IpAddr::V6)
                        .collect::<Vec<_>>()
                        .into_iter(),
                ),
                DnsResponseInner::A(ipv4_addrs) => Some(
                    // TODO: Instead of cloned, can these be references?
                    ipv4_addrs
                        .as_ref()
                        .ok()?
                        .iter()
                        .cloned()
                        .map(IpAddr::V4)
                        .collect::<Vec<_>>()
                        .into_iter(),
                ),
            })
            .flatten()
            .filter(|ip| {
                !self
                    .connection_attempts
                    .iter()
                    .any(|(attempted_ip, _)| attempted_ip == ip)
            })
            .collect::<Vec<_>>();
        ips.sort_by_key(|ip| (ip.is_ipv6() != self.network_config.prefer_v6()) as u8);

        let ip = ips.into_iter().next()?;

        self.connection_attempts.push((ip, now));
        // TODO: Should we attempt connecting to HTTPS RR IP hints?

        // TODO: What if we already made that connection attempt?
        Some(Output::AttemptConnection {
            address: SocketAddr::new(ip, self.target.1),
        })
    }

    /// Whether to move on to the connection attempt phase based on the received
    /// DNS responses, not based on a timeout.
    fn move_on_without_timeout(&mut self) -> bool {
        if self
            .dns_queries
            .iter()
            .any(|q| *q.target_name() != self.target.0)
        {
            debug_assert!(
                false,
                "function currently can't handle different target names"
            );
            return false;
        }

        // > Some positive (non-empty) address answers have been received AND
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        if !self.dns_queries.iter().any(|q| match q {
            DnsQuery::Completed { response } => match &response.inner {
                DnsResponseInner::Aaaa(Ok(addrs)) => !addrs.is_empty(),
                DnsResponseInner::A(Ok(addrs)) => !addrs.is_empty(),
                DnsResponseInner::Https(Ok(infos)) => infos
                    .iter()
                    .any(|i| !i.ipv4_hints.is_empty() || !i.ipv6_hints.is_empty()),

                _ => false,
            },
            _ => false,
        }) {
            return false;
        }

        // > A postive (non-empty) or negative (empty) answer has been received
        // > for the preferred address family that was queried AND
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        if !self
            .dns_queries
            .iter()
            .filter(|q| matches!(q, DnsQuery::Completed { .. }))
            .any(|q| q.record_type() == self.network_config.preferred_dns_record_type())
        {
            return false;
        }

        // > SVCB/HTTPS service information has been received (or has received a negative response)
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
        if !self
            .dns_queries
            .iter()
            .filter(|q| matches!(q, DnsQuery::Completed { .. }))
            .any(|q| q.record_type() == DnsRecordType::Https)
        {
            return false;
        }

        true
    }

    /// Whether to move on to the connection attempt phase based on a timeout.
    fn move_on_with_timeout(&mut self, now: Instant) -> bool {
        if self
            .dns_queries
            .iter()
            .any(|q| *q.target_name() != self.target.0)
        {
            debug_assert!(
                false,
                "function currently can't handle different target names"
            );
            return false;
        }

        // > Or:
        // >
        // > - Some positive (non-empty) address answers have been received AND
        // > - A resolution time delay has passed after which other answers have not been received
        //
        // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>

        let mut positive_responses = self
            .dns_queries
            .iter()
            .filter_map(|q| q.get_response())
            .filter(|r| r.positive())
            .filter(|r| matches!(r.record_type(), DnsRecordType::Aaaa | DnsRecordType::A))
            .peekable();

        if positive_responses.peek().is_none() {
            return false;
        }

        let Some(https_query) = self
            .dns_queries
            .iter()
            .find(|q| q.record_type() == DnsRecordType::Https)
        else {
            return false;
        };
        match https_query {
            DnsQuery::InProgress {
                started,
                target_name,
                record_type,
            } if now.duration_since(*started) >= RESOLUTION_DELAY => {}
            _ => {
                return false;
            }
        }

        true
    }
}
