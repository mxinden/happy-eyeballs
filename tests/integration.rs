use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use happy_eyeballs::{
    DnsRecordType, DnsResponse, DnsResponseInner, Endpoint, HappyEyeballs, HttpVersions, Input,
    IpPreference, NetworkConfig, Output,
};

// TODO: Handle difference between com. and com? Use library for hostnames?!
const HOSTNAME: &str = "example.com.";
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
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: "example.com.".into(),
            alpn_protocols: vec!["h3".to_string(), "h2".to_string()],
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_positive_v6_hints() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: "example.com.".into(),
            alpn_protocols: vec!["h3".to_string(), "h2".to_string()],
            ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_positive_svc1() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Https(Ok(vec![happy_eyeballs::ServiceInfo {
            priority: 1,
            target_name: "svc1.example.com.".into(),
            alpn_protocols: vec!["h3".to_string(), "h2".to_string()],
            ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)],
            ipv4_hints: vec![],
            ech_config: None,
        }])),
    })
}

fn in_dns_https_negative() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Https(Err(())),
    })
}

fn in_dns_aaaa_positive() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Aaaa(Ok(vec![V6_ADDR])),
    })
}

fn in_dns_a_positive() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::A(Ok(vec![V4_ADDR])),
    })
}

fn in_dns_aaaa_negative() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::Aaaa(Err(())),
    })
}

fn in_dns_a_negative() -> Input {
    Input::DnsResponse(DnsResponse {
        target_name: "example.com.".into(),
        inner: DnsResponseInner::A(Err(())),
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
        endpoint: Endpoint::new(SocketAddr::new(V6_ADDR.into(), PORT)),
    }
}

fn out_attempt_v4() -> Output {
    Output::AttemptConnection {
        endpoint: Endpoint::new(SocketAddr::new(V4_ADDR.into(), PORT)),
    }
}

fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let now = Instant::now();
    let he = HappyEyeballs::with_network_config(HOSTNAME.to_string(), PORT, config);
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
    use happy_eyeballs::{CONNECTION_ATTEMPT_DELAY, RESOLUTION_DELAY};

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
            for https in [in_dns_https_positive(), in_dns_https_negative()] {
                let (now, mut he) = setup_with_config(test_case.address_family.clone());

                he.expect(
                    vec![
                        (None, Some(out_send_dns_https())),
                        (None, Some(out_send_dns_aaaa())),
                        (None, Some(out_send_dns_a())),
                        (Some(test_case.positive.clone()), None),
                        (test_case.preferred.clone(), None),
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
    fn https_hints() {
        let (now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_aaaa_negative()), None),
                (Some(in_dns_a_negative()), None),
                (
                    Some(in_dns_https_positive_v6_hints()),
                    Some(out_attempt_v6()),
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
    fn multiple_ips_per_record() {
        let (mut now, mut he) = setup();

        he.expect(
            vec![
                (None, Some(out_send_dns_https())),
                (None, Some(out_send_dns_aaaa())),
                (None, Some(out_send_dns_a())),
                (Some(in_dns_https_negative()), None),
                (Some(in_dns_a_negative()), None),
                (
                    Some(Input::DnsResponse(DnsResponse {
                        target_name: "example.com.".into(),
                        inner: DnsResponseInner::Aaaa(Ok(vec![V6_ADDR, V6_ADDR_2, V6_ADDR_3])),
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
                    endpoint: Endpoint::new(SocketAddr::new(V6_ADDR_2.into(), PORT)),
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
                (Some(in_dns_https_positive()), None),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
                (Some(in_dns_a_positive()), None),
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
                (Some(in_dns_https_negative()), None),
                (Some(in_dns_a_negative()), None),
                (Some(in_dns_aaaa_positive()), Some(out_attempt_v6())),
            ],
            now,
        );

        now += CONNECTION_ATTEMPT_DELAY;

        he.expect(vec![(None, None)], now);
    }
}
