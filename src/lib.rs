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
//! # use happy_eyeballs::{
//! #     DnsRecordType, DnsResponse, DnsResponseInner, HappyEyeballs, Input, NetworkConfig,
//! #     HttpVersions, IpPreference, Output, Protocol, ServiceInfo, TargetName,
//! # };
//! # use std::{
//! #     collections::HashSet,
//! #     net::{Ipv4Addr, Ipv6Addr},
//! #     time::Instant,
//! # };
//!
//! let mut he = HappyEyeballs::new("example.com".into(), 443).unwrap();
//!
//! let mut now = Instant::now();
//! let mut input = None;
//! loop {
//!     match he.process(input.take(), now) {
//!         None => break, // nothing more to do right now
//!         Some(Output::SendDnsQuery { hostname, record_type }) => {
//!             let response = match record_type {
//!                 DnsRecordType::Https => {
//!                     let mut alpn = HashSet::new();
//!                     alpn.insert(Protocol::H3);
//!                     alpn.insert(Protocol::H2);
//!                     DnsResponse {
//!                         target_name: hostname.clone(),
//!                         inner: DnsResponseInner::Https(Ok(vec![ServiceInfo {
//!                             priority: 1,
//!                             target_name: TargetName::from("example.com"),
//!                             alpn_protocols: alpn,
//!                             ech_config: None,
//!                             ipv4_hints: vec![Ipv4Addr::new(192, 0, 2, 1)],
//!                             ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
//!                         }])),
//!                     }
//!                 }
//!                 DnsRecordType::Aaaa => DnsResponse {
//!                     target_name: hostname.clone(),
//!                     inner: DnsResponseInner::Aaaa(Ok(vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
//!                 },
//!                 DnsRecordType::A => DnsResponse {
//!                     target_name: hostname.clone(),
//!                     inner: DnsResponseInner::A(Ok(vec![Ipv4Addr::new(192, 0, 2, 1)])),
//!                 },
//!             };
//!             input = Some(Input::DnsResponse(response));
//!         }
//!         Some(Output::AttemptConnection { endpoint }) => {
//!             let _ = he.process(
//!                 Some(Input::ConnectionResult { address: endpoint.address, result: Ok(()) }),
//!                 now,
//!             );
//!             break;
//!         }
//!         Some(Output::CancelConnection(_addr)) => {}
//!         Some(Output::Timer { duration }) => {
//!             now += duration;
//!         }
//!     }
//! }
//! ```

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{Level, instrument, trace};
use url::Host;

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

    fn flatten_into_endpoints(
        &self,
        port: u16,
        got_a: bool,
        got_aaaa: bool,
        protocols: HashSet<Protocol>,
    ) -> Vec<Endpoint> {
        match self {
            DnsResponseInner::Https(infos) => infos
                .as_ref()
                .ok()
                .into_iter()
                .flat_map(|infos| {
                    infos
                        .iter()
                        .flat_map(|info| info.flatten_into_endpoints(port, got_a, got_aaaa))
                })
                // TODO: way around allocation?
                .collect(),
            DnsResponseInner::Aaaa(ipv6_addrs) => ipv6_addrs
                .as_ref()
                .ok()
                .into_iter()
                .flat_map(|addrs| {
                    addrs.iter().cloned().flat_map(|ip| {
                        protocols.iter().map(move |p| Endpoint {
                            address: SocketAddr::new(IpAddr::V6(ip), port),
                            protocol: *p,
                        })
                    })
                })
                // TODO: way around allocation?
                .collect(),
            DnsResponseInner::A(ipv4_addrs) => ipv4_addrs
                .as_ref()
                .ok()
                .into_iter()
                .flat_map(|addrs| {
                    addrs.iter().cloned().flat_map(|ip| {
                        protocols.iter().map(move |p| Endpoint {
                            address: SocketAddr::new(IpAddr::V4(ip), port),
                            protocol: *p,
                        })
                    })
                })
                // TODO: way around allocation?
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TargetName(String);

impl From<&str> for TargetName {
    fn from(s: &str) -> Self {
        TargetName(s.to_string())
    }
}

impl From<TargetName> for String {
    fn from(t: TargetName) -> Self {
        t.0
    }
}

impl Debug for TargetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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
    Timer { duration: Duration },

    /// Attempt to connect to an address
    AttemptConnection { endpoint: Endpoint },

    // TODO: Consider a CancelSendDnsQuery.
    /// Cancel a connection attempt
    CancelConnection(SocketAddr),
    // TODO: Should there be an event for giving up?
}

impl Output {
    pub fn attempt(self) -> Option<Endpoint> {
        match self {
            Output::AttemptConnection { endpoint } => Some(endpoint),
            _ => None,
        }
    }
}

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    Https,
    Aaaa,
    A,
}

/// Service information from HTTPS records
#[derive(Clone, PartialEq)]
pub struct ServiceInfo {
    pub priority: u16,
    pub target_name: TargetName,
    pub alpn_protocols: HashSet<Protocol>,
    pub ech_config: Option<Vec<u8>>,
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
}

impl Debug for ServiceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServiceInfo");

        debug_struct.field("priority", &self.priority);
        debug_struct.field("target", &self.target_name);

        if !self.alpn_protocols.is_empty() {
            debug_struct.field("alpn", &self.alpn_protocols);
        }

        if self.ech_config.is_some() {
            debug_struct.field("ech", &self.ech_config);
        }

        if !self.ipv4_hints.is_empty() {
            debug_struct.field("ipv4", &self.ipv4_hints);
        }

        if !self.ipv6_hints.is_empty() {
            debug_struct.field("ipv6", &self.ipv6_hints);
        }

        debug_struct.finish()
    }
}

impl ServiceInfo {
    fn flatten_into_endpoints(&self, port: u16, got_a: bool, got_aaaa: bool) -> Vec<Endpoint> {
        self.ipv6_hints
            .iter()
            .cloned()
            .map(IpAddr::V6)
            .chain(self.ipv4_hints.iter().cloned().map(IpAddr::V4))
            // > ServiceMode records can contain address hints via ipv6hint and
            // > ipv4hint parameters. When these are received, they SHOULD be
            // > considered as positive non-empty answers for the purpose of the
            // > algorithm when A and AAAA records corresponding to the TargetName
            // > are not available yet.
            //
            // <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
            .filter(|ip| match ip {
                IpAddr::V6(_) => !got_aaaa,
                IpAddr::V4(_) => !got_a,
            })
            .flat_map(|ip| {
                self.alpn_protocols.iter().map(move |alpn| Endpoint {
                    address: SocketAddr::new(ip, port),
                    // TODO: Only take the overlap with HappyEyeballs::protocols().
                    protocol: *alpn,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    H3,
    H2,
    H1,
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

#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub endpoint: Endpoint,
    pub started: Instant,
}

impl ConnectionAttempt {
    fn within_delay(&self, now: Instant) -> bool {
        now.duration_since(self.started) < CONNECTION_ATTEMPT_DELAY
    }
}

/// All information (IP, protocol, ...) needed to attempt a connection to a specific endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub address: SocketAddr,
    // TODO: Currently just taking H2, when really it should be H1 and H2. Is that a problem?
    pub protocol: Protocol,
}

impl Endpoint {
    fn sort_with_config(&self, other: &Endpoint, network_config: &NetworkConfig) -> Ordering {
        if self.protocol != other.protocol {
            return self.protocol.cmp(&other.protocol);
        }

        let order = self
            .address
            .ip()
            .is_ipv6()
            .cmp(&other.address.ip().is_ipv6());
        if network_config.prefer_v6() {
            order.reverse()
        } else {
            order
        }
    }
}

/// Happy Eyeballs v3 state machine
pub struct HappyEyeballs {
    dns_queries: Vec<DnsQuery>,
    connection_attempts: Vec<ConnectionAttempt>,
    /// Network configuration
    network_config: NetworkConfig,
    host: Host,
    port: u16,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct ConstructorError {
    inner: ConstructorErrorInner,
}

impl From<ConstructorErrorInner> for ConstructorError {
    fn from(inner: ConstructorErrorInner) -> Self {
        Self { inner }
    }
}

#[derive(Error, Debug)]
enum ConstructorErrorInner {
    #[error("invalid host: {0}")]
    InvalidHost(#[from] url::ParseError),
}

impl std::fmt::Debug for HappyEyeballs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("HappyEyeballs");

        // Always include target and network configuration.
        ds.field("target", &self.host);
        ds.field("port", &self.port);
        ds.field("network_config", &self.network_config);

        // Only include vectors when non-empty to reduce noise.
        if !self.dns_queries.is_empty() {
            ds.field("dns_queries", &self.dns_queries);
        }
        if !self.connection_attempts.is_empty() {
            ds.field("connection_attempts", &self.connection_attempts);
        }

        ds.finish()
    }
}

impl HappyEyeballs {
    /// Create a new Happy Eyeballs state machine with default network config
    pub fn new(host: &str, port: u16) -> Result<Self, ConstructorError> {
        Self::new_with_network_config(host, port, NetworkConfig::default())
    }

    /// Create a new Happy Eyeballs state machine with custom network configuration
    #[instrument(skip_all, level = Level::TRACE, fields(target = host), ret)]
    pub fn new_with_network_config(
        host: &str,
        port: u16,
        network_config: NetworkConfig,
    ) -> Result<Self, ConstructorError> {
        let host = Host::parse(host).map_err(ConstructorErrorInner::InvalidHost)?;
        Ok(Self {
            network_config,
            dns_queries: Vec::new(),
            connection_attempts: Vec::new(),
            host,
            port,
        })
    }

    // TODO: Does this ever return None given the timeouts?
    /// Process an input event and return the corresponding output
    ///
    /// Call with `None` to advance the state machine and get any pending outputs.
    /// Call with `Some(input)` to provide external input (DNS results, timers, etc.).
    ///
    /// The caller must call [`HappyEyeballs::process`] with input [`None`]
    /// until it returns [`None`] or [`Output::Timer`].
    #[instrument(skip_all, level = Level::TRACE, fields(target = %self.host), ret)]
    pub fn process(&mut self, input: Option<Input>, now: Instant) -> Option<Output> {
        trace!(input = ?input);

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

        let output = self.timer(now);
        if output.is_some() {
            return output;
        }

        None
    }

    fn timer(&self, now: Instant) -> Option<Output> {
        let resolution_delay = self
            .dns_queries
            .iter()
            .filter_map(|q| match q {
                DnsQuery::InProgress {
                    started,
                    target_name: _,
                    record_type: _,
                } => Some(started),
                _ => None,
            })
            .max()
            .and_then(|started| {
                let elapsed = now.duration_since(*started);
                if elapsed < RESOLUTION_DELAY {
                    Some(RESOLUTION_DELAY - elapsed)
                } else {
                    None
                }
            });

        let connection_attempt_delay = self
            .connection_attempts
            .iter()
            .map(|a| &a.started)
            .max()
            .and_then(|started| {
                let elapsed = now.duration_since(*started);
                if elapsed < CONNECTION_ATTEMPT_DELAY {
                    Some(CONNECTION_ATTEMPT_DELAY - elapsed)
                } else {
                    None
                }
            });

        match (resolution_delay, connection_attempt_delay) {
            (Some(rd), Some(cad)) => Some(rd.min(cad)),
            (Some(rd), None) => Some(rd),
            (None, Some(cad)) => Some(cad),
            (None, None) => None,
        }
        .map(|duration| Output::Timer { duration })
    }

    fn send_dns_request(&mut self, now: Instant) -> Option<Output> {
        let target_name: TargetName = match &self.host {
            Host::Ipv4(_) | Host::Ipv6(_) => {
                // No DNS queries needed for IP hosts.
                return None;
            }
            Host::Domain(domain) => domain.as_str(),
        }
        .into();

        // TODO: What if v4 or v6 is disabled? Don't send the query.
        for record_type in [DnsRecordType::Https, DnsRecordType::Aaaa, DnsRecordType::A] {
            if !self
                .dns_queries
                .iter()
                .any(|q| q.record_type() == record_type)
            {
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

        None
    }

    // TODO: Limit number of target names.
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
        move_on |= matches!(self.host, Host::Ipv4(_) | Host::Ipv6(_));
        if !move_on {
            return None;
        }

        if self.connection_attempts.iter().any(|a| a.within_delay(now)) {
            return None;
        }
        let endpoint = self.next_endpoint_to_attempt()?;

        self.connection_attempts.push(ConnectionAttempt {
            endpoint: endpoint.clone(),
            started: now,
        });

        Some(Output::AttemptConnection { endpoint })
    }

    fn next_endpoint_to_attempt(&self) -> Option<Endpoint> {
        match self.host {
            Host::Ipv4(ipv4_addr) => {
                let protocols = self.protocols();
                return Some(Endpoint {
                    address: SocketAddr::new(IpAddr::V4(ipv4_addr), self.port),
                    protocol: *protocols.iter().next()?,
                });
            }
            Host::Ipv6(ipv6_addr) => {
                let protocols = self.protocols();
                return Some(Endpoint {
                    address: SocketAddr::new(IpAddr::V6(ipv6_addr), self.port),
                    protocol: *protocols.iter().next()?,
                });
            }
            Host::Domain(_) => {}
        }

        let got_a = self.got_dns_a_response();
        let got_aaaa = self.got_dns_aaaa_response();
        let mut endpoints = self
            .dns_queries
            .iter()
            .filter_map(|q| q.get_response())
            .flat_map(|r| {
                r.inner
                    .flatten_into_endpoints(self.port, got_a, got_aaaa, self.protocols())
            })
            .filter(|endpoint| {
                !self
                    .connection_attempts
                    .iter()
                    .any(|attempt| attempt.endpoint == *endpoint)
            })
            .collect::<Vec<_>>();
        endpoints.sort_by(|a, b| a.sort_with_config(b, &self.network_config));
        endpoints.into_iter().next()
    }

    fn got_dns_aaaa_response(&self) -> bool {
        self.dns_queries
            .iter()
            .filter(|q| {
                *q.target_name()
                    == match &self.host {
                        Host::Domain(d) => d.as_str().into(),
                        Host::Ipv4(_ipv4_addr) => todo!(),
                        Host::Ipv6(_ipv6_addr) => todo!(),
                    }
            })
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
            })
    }

    fn got_dns_a_response(&self) -> bool {
        self.dns_queries
            .iter()
            .filter(|q| {
                *q.target_name()
                    == match &self.host {
                        Host::Domain(d) => d.as_str().into(),
                        Host::Ipv4(_ipv4_addr) => todo!(),
                        Host::Ipv6(_ipv6_addr) => todo!(),
                    }
            })
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
            })
    }

    fn protocols(&self) -> HashSet<Protocol> {
        // TODO: assuming h2. correct?
        let mut protocols = HashSet::from([Protocol::H2]);
        for alpn in self.dns_queries.iter().filter_map(|q| match q {
            DnsQuery::Completed {
                response:
                    DnsResponse {
                        inner: DnsResponseInner::Https(Ok(infos)),
                        ..
                    },
            } => Some(
                infos
                    .iter()
                    .flat_map(|i| i.alpn_protocols.iter().cloned())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        }) {
            for protocol in alpn {
                protocols.insert(protocol);
            }
        }
        if !self.network_config.http_versions.h3 {
            protocols.remove(&Protocol::H3);
        }
        if !self.network_config.http_versions.h2 {
            protocols.remove(&Protocol::H2);
        }
        if !self.network_config.http_versions.h1 {
            protocols.remove(&Protocol::H1);
        }
        protocols
    }

    /// Whether to move on to the connection attempt phase based on the received
    /// DNS responses, not based on a timeout.
    fn move_on_without_timeout(&mut self) -> bool {
        if self.dns_queries.iter().any(|q| {
            *q.target_name()
                != match &self.host {
                    Host::Domain(d) => d.as_str().into(),
                    Host::Ipv4(_ipv4_addr) => todo!(),
                    Host::Ipv6(_ipv6_addr) => todo!(),
                }
        }) {
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
        if self.dns_queries.iter().any(|q| {
            *q.target_name()
                != match &self.host {
                    Host::Domain(d) => d.as_str().into(),
                    Host::Ipv4(_ipv4_addr) => todo!(),
                    Host::Ipv6(_ipv6_addr) => todo!(),
                }
        }) {
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
