use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, DnsRecordType, DnsResult, DnsResultInner, Endpoint, HappyEyeballs,
    HttpVersions, Input, IpPreference, NetworkConfig, Output, Protocol, ProtocolCombination,
    RESOLUTION_DELAY,
};
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

// TODO: Should crate treat "example.com" and "example.com." the same?
const HOSTNAME: &str = "example.com";
const PORT: u16 = 443;
const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_ADDR_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const V6_ADDR_3: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

trait HappyEyeballsExt {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant);
}

impl HappyEyeballsExt for HappyEyeballs {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant) {
        for (input, expected_output) in input_output {
            let output = self.process(input, now);
            assert_eq!(expected_output, output);
        }
    }
}

fn in_dns_https_positive() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_protocols: HashSet::from([Protocol::H3, Protocol::H2]),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_positive_no_alpn() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_protocols: HashSet::new(),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_positive_v6_hints() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_protocols: HashSet::from([Protocol::H3, Protocol::H2]),
            ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_positive_svc1() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: "svc1.example.com.".into(),
            alpn_protocols: HashSet::from([Protocol::H3, Protocol::H2]),
            ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_negative() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Https(Err(())),
    })
}

fn in_dns_aaaa_positive() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Aaaa(Ok(vec![V6_ADDR])),
    })
}

fn in_dns_a_positive() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::A(Ok(vec![V4_ADDR])),
    })
}

fn in_dns_aaaa_negative() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::Aaaa(Err(())),
    })
}

fn in_dns_a_negative() -> Input {
    Input::DnsResult(DnsResult {
        target_name: HOSTNAME.into(),
        inner: DnsResultInner::A(Err(())),
    })
}

fn out_send_dns_https() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Https,
    }
}

fn out_send_dns_aaaa() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Aaaa,
    }
}

fn out_send_dns_svc1() -> Output {
    Output::SendDnsQuery {
        hostname: "svc1.example.com.".into(),
        record_type: DnsRecordType::Aaaa,
    }
}

fn out_send_dns_a() -> Output {
    Output::SendDnsQuery {
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::A,
    }
}

fn out_attempt_v6() -> Output {
    Output::AttemptConnection {
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            protocol: ProtocolCombination::H2OrH1,
        },
    }
}

fn out_attempt_v6_h3() -> Output {
    Output::AttemptConnection {
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            protocol: ProtocolCombination::H3,
        },
    }
}

fn out_attempt_v4() -> Output {
    Output::AttemptConnection {
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            protocol: ProtocolCombination::H2OrH1,
        },
    }
}

fn out_resolution_delay() -> Output {
    Output::Timer {
        duration: RESOLUTION_DELAY,
    }
}

fn out_connection_attempt_delay() -> Output {
    Output::Timer {
        duration: CONNECTION_ATTEMPT_DELAY,
    }
}

fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let _ = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        // Build the subscriber
        .finish()
        .try_init();

    let now = Instant::now();
    let he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();
    (now, he)
}

#[test]
fn initial_state() {
    let (now, mut he) = setup();

    he.expect(vec![(None, Some(out_send_dns_https()))], now);
}

// TODO: Move to own file?
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
                (Some(in_dns_https_positive()), Some(out_resolution_delay())),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6_h3())),
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
    /// >   received for the preferred address family that was queried AND
    /// > - SVCB/HTTPS service information has been received (or has received a negative response)
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
    #[test]
    fn move_on_non_timeout() {
        #[derive(Debug)]
        struct Case {
            address_family: NetworkConfig,
            positive: Input,
            preferred: Option<Input>,
            expected: Option<Output>,
        }

        let test_cases = vec![
            // V6 preferred, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV6,
                },
                positive: in_dns_aaaa_positive(),
                preferred: None,
                expected: Some(out_attempt_v6()),
            },
            // V6 preferred, V4 positive, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV6,
                },
                positive: in_dns_a_positive(),
                preferred: Some(in_dns_aaaa_positive()),
                expected: Some(out_attempt_v6()),
            },
            // V6 preferred, V6 negative, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV6,
                },
                positive: in_dns_a_positive(),
                preferred: Some(in_dns_aaaa_negative()),
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV4,
                },
                positive: in_dns_a_positive(),
                preferred: None,
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V6 positive, V4 positive, HTTPS positive, expect V4 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV4,
                },
                positive: in_dns_aaaa_positive(),
                preferred: Some(in_dns_a_positive()),
                expected: Some(out_attempt_v4()),
            },
            // V4 preferred, V4 negative, V6 positive, HTTPS positive, expect V6 connection attempt
            Case {
                address_family: NetworkConfig {
                    http_versions: HttpVersions::default(),
                    ip: IpPreference::DualStackPreferV4,
                },
                positive: in_dns_aaaa_positive(),
                preferred: Some(in_dns_a_negative()),
                expected: Some(out_attempt_v6()),
            },
        ];

        for test_case in test_cases {
            for https in [in_dns_https_positive_no_alpn(), in_dns_https_negative()] {
                let (now, mut he) = setup_with_config(test_case.address_family.clone());

                he.expect(
                    vec![
                        (None, Some(out_send_dns_https())),
                        (None, Some(out_send_dns_aaaa())),
                        (None, Some(out_send_dns_a())),
                        (
                            Some(test_case.positive.clone()),
                            Some(out_resolution_delay()),
                        ),
                        (test_case.preferred.clone(), Some(out_resolution_delay())),
                        (Some(https), test_case.expected.clone()),
                    ],
                    now,
                );
            }
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
                (Some(in_dns_a_positive()), Some(out_resolution_delay())),
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
    fn https_hints() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_aaaa_negative()), Some(out_resolution_delay())),
                (Some(in_dns_a_negative()), Some(out_resolution_delay())),
                (
                    Some(in_dns_https_positive_v6_hints()),
                    Some(out_attempt_v6_h3()),
                ),
            ],
            now,
        );
    }

    /// > Note that clients are still required to issue A and AAAA queries
    /// > for those TargetNames if they haven't yet received those records.
    ///
    /// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
    #[test]
    fn https_hints_still_query_a_aaaa() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (
                    Some(in_dns_https_positive_svc1()),
                    Some(out_send_dns_svc1()),
                ),
            ],
            now,
        );
    }

    #[test]
    fn https_h3_upgrade_without_hints() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_aaaa_positive()), Some(out_resolution_delay())),
                (Some(in_dns_https_positive()), Some(out_attempt_v6_h3())),
            ],
            now,
        );
    }

    #[test]
    fn multiple_ips_per_record() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_https_negative()), Some(out_resolution_delay())),
                (Some(in_dns_a_negative()), Some(out_resolution_delay())),
                (
                    Some(Input::DnsResult(DnsResult {
                        target_name: HOSTNAME.into(),
                        inner: DnsResultInner::Aaaa(Ok(vec![V6_ADDR, V6_ADDR_2, V6_ADDR_3])),
                    })),
                    Some(out_attempt_v6()),
                ),
            ],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;

        he.expect(
            vec![(
                None,
                Some(Output::AttemptConnection {
                    endpoint: Endpoint {
                        address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                        protocol: ProtocolCombination::H2OrH1,
                    },
                }),
            )],
            now,
        );
    }
}

// TODO: Move to own file?
mod section_6_connection_attempts {
    use happy_eyeballs::CONNECTION_ATTEMPT_DELAY;

    use super::*;

    #[test]
    fn connection_attempt_delay() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (
                    Some(in_dns_https_positive_no_alpn()),
                    Some(out_resolution_delay()),
                ),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
                (
                    Some(in_dns_a_positive()),
                    Some(out_connection_attempt_delay()),
                ),
            ],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;

        he.expect(vec![(None, Some(out_attempt_v4()))], now);
    }

    #[test]
    fn never_try_same_attempt_twice() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_https_negative()), Some(out_resolution_delay())),
                (Some(in_dns_a_negative()), Some(out_resolution_delay())),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
            ],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;

        he.expect(vec![(None, None)], now);
    }

    #[test]
    fn successful_connection_cancels_others() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (
                    Some(in_dns_https_positive_no_alpn()),
                    Some(out_resolution_delay()),
                ),
                (
                    Some(Input::DnsResult(DnsResult {
                        target_name: HOSTNAME.into(),
                        inner: DnsResultInner::Aaaa(Ok(vec![V6_ADDR, V6_ADDR_2])),
                    })),
                    Some(out_attempt_v6()),
                ),
                (
                    Some(in_dns_a_positive()),
                    Some(out_connection_attempt_delay()),
                ),
            ],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;
        he.expect(
            vec![(
                None,
                Some(Output::AttemptConnection {
                    endpoint: Endpoint {
                        address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                        protocol: ProtocolCombination::H2OrH1,
                    },
                }),
            )],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;
        he.expect(vec![(None, Some(out_attempt_v4()))], now);
        he.expect(
            vec![
                (
                    Some(Input::ConnectionResult {
                        address: SocketAddr::new(V6_ADDR.into(), PORT),
                        result: Ok(()),
                    }),
                    Some(Output::CancelConnection(SocketAddr::new(
                        V6_ADDR_2.into(),
                        PORT,
                    ))),
                ),
                (
                    None,
                    Some(Output::CancelConnection(SocketAddr::new(
                        V4_ADDR.into(),
                        PORT,
                    ))),
                ),
                (None, None),
            ],
            now,
        );
    }

    #[test]
    fn failed_connection_tries_next_immediately() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (
                    Some(in_dns_https_positive_no_alpn()),
                    Some(out_resolution_delay()),
                ),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
                (
                    Some(in_dns_a_positive()),
                    Some(out_connection_attempt_delay()),
                ),
            ],
            now,
        );

        he.expect(
            vec![(
                Some(Input::ConnectionResult {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    result: Err("connection refused".to_string()),
                }),
                Some(out_attempt_v4()),
            )],
            now,
        );
    }
}

#[test]
fn ipv6_blackhole() {
    let (mut now, mut he) = setup();

    he.expect(
        vec![
            (None, Some(out_send_dns_https())),
            (None, Some(out_send_dns_aaaa())),
            (None, Some(out_send_dns_a())),
            (Some(in_dns_https_positive()), Some(out_resolution_delay())),
            (Some(in_dns_a_positive()), Some(out_resolution_delay())),
            (Some(in_dns_aaaa_positive()), Some(out_attempt_v6_h3())),
        ],
        now,
    );

    for _ in 0..42 {
        now += CONNECTION_ATTEMPT_DELAY;
        let connection_attempt = he.process(None, now).unwrap().attempt().unwrap();
        if connection_attempt.address.is_ipv4() {
            return;
        }
    }

    panic!("Did not fall back to IPv4.");
}

#[test]
fn ip_host() {
    let now = Instant::now();
    let mut he = HappyEyeballs::new("[2001:0DB8::1]", PORT).unwrap();

    he.expect(vec![(None, Some(out_attempt_v6()))], now);
}

#[test]
fn not_url_but_ip() {
    // Neither of these are a valid URL, but they are valid IP addresses.
    HappyEyeballs::new("::1", PORT).unwrap();
    HappyEyeballs::new("127.0.0.1", PORT).unwrap();
}
