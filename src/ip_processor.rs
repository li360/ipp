use ipnetwork::{IpNetwork as ExternalIpNetwork, IpNetworkError};
use rand;
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum IpInput {
    Cidr(ExternalIpNetwork),
    Single(IpAddr),
    Range((IpAddr, IpAddr)),
}

use std::io;
use std::net::AddrParseError;

#[derive(Debug)]
pub enum IpProcessorError {
    InvalidInput,
    ParseError(IpNetworkError),
    IoError(io::Error),
    AddrParseError(AddrParseError),
}

impl From<IpNetworkError> for IpProcessorError {
    fn from(err: IpNetworkError) -> Self {
        IpProcessorError::ParseError(err)
    }
}

impl From<io::Error> for IpProcessorError {
    fn from(err: io::Error) -> Self {
        IpProcessorError::IoError(err)
    }
}

impl From<AddrParseError> for IpProcessorError {
    fn from(err: AddrParseError) -> Self {
        IpProcessorError::AddrParseError(err)
    }
}

pub struct IpProcessor;

impl IpProcessor {
    pub fn is_network_address(ip: IpAddr, network: ExternalIpNetwork) -> bool {
        ip == network.network()
    }

    pub fn parse_input(input: &str) -> Result<IpInput, IpProcessorError> {
        // Try parsing as CIDR first
        if let Ok(network) = ExternalIpNetwork::from_str(input) {
            return Ok(IpInput::Cidr(network));
        }

        // Try parsing as IP range
        if let Some((start, end)) = input.split_once('-') {
            let start_ip = IpAddr::from_str(start.trim())?;

            // Handle short form (e.g. 192.168.1.1-10)
            if let Ok(end_num) = end.trim().parse::<u8>() {
                let mut octets = match start_ip {
                    IpAddr::V4(v4) => v4.octets(),
                    _ => return Err(IpProcessorError::InvalidInput),
                };
                octets[3] = end_num;
                let end_ip = IpAddr::from(octets);
                return Ok(IpInput::Range((start_ip, end_ip)));
            }

            // Handle full IP format
            let end_ip = IpAddr::from_str(end.trim())?;
            return Ok(IpInput::Range((start_ip, end_ip)));
        }

        // Try parsing as single IP
        if let Ok(ip) = IpAddr::from_str(input) {
            return Ok(IpInput::Single(ip));
        }

        Err(IpProcessorError::InvalidInput)
    }

    pub fn generate_ips(input: IpInput, include_all: bool, max_ips: usize) -> Vec<IpAddr> {
        match input {
            IpInput::Single(ip) => vec![ip],
            IpInput::Cidr(network) => Self::generate_cidr_ips(network, include_all, max_ips),
            IpInput::Range((start, end)) => Self::generate_range_ips(start, end, max_ips),
        }
    }

    fn generate_cidr_ips(
        network: ExternalIpNetwork,
        include_all: bool,
        max_ips: usize,
    ) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        let mut count = 0;

        for ip in network.iter() {
            if !include_all && (ip == network.network() || ip == network.broadcast()) {
                continue;
            }
            if count >= max_ips {
                break;
            }
            ips.push(ip);
            count += 1;
        }

        ips
    }

    fn generate_range_ips(start: IpAddr, end: IpAddr, max_ips: usize) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        let mut current = start;
        let mut count = 0;

        while current <= end && count < max_ips {
            ips.push(current);
            current = Self::increment_ip(current);
            count += 1;
        }

        ips
    }

    fn increment_ip(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let mut octets = v4.octets();
                for i in (0..4).rev() {
                    if octets[i] < 255 {
                        octets[i] += 1;
                        break;
                    } else {
                        octets[i] = 0;
                    }
                }
                IpAddr::from(octets)
            }
            IpAddr::V6(v6) => {
                let mut segments = v6.segments();
                for i in (0..8).rev() {
                    if segments[i] < 0xFFFF {
                        segments[i] += 1;
                        break;
                    } else {
                        segments[i] = 0;
                    }
                }
                IpAddr::from(segments)
            }
        }
    }

    pub fn check_port(ip: IpAddr, port: u16, timeout: Duration) -> Option<u64> {
        let start = std::time::Instant::now();
        match TcpStream::connect_timeout(&(ip, port).into(), timeout) {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    }

    pub fn single_ip_test(ip: IpAddr, timeout: Duration) -> Vec<u64> {
        let mut results = Vec::new();
        for _ in 0..10 {
            let start = std::time::Instant::now();
            if TcpStream::connect_timeout(&(ip, 80).into(), timeout).is_ok() {
                let duration = start.elapsed().as_millis() as u64;
                results.push(duration);
            } else {
                results.push(0);
            }
        }
        results
    }

    pub fn draw_ping_graph(results: &[u64]) -> String {
        let max = *results.iter().max().unwrap_or(&1);
        let scale = 10.0 / max as f64;

        results
            .iter()
            .map(|&val| {
                let height = (val as f64 * scale).round() as usize;
                format!("{:>4}ms |{}", val, "▇".repeat(height))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub async fn single_ip_test_once(ip: IpAddr, timeout: Duration) -> Result<u64, IpProcessorError> {
        // 如果是本地地址，直接返回1ms延迟
        if let Ok(local_ip) = local_ip_address::local_ip() {
            if ip == local_ip {
                return Ok(1);
            }
        }

        // 使用surge-ping进行ICMP ping
        let payload = [0; 56];
        let client = surge_ping::Client::new(&Default::default())?;
        let identifier = surge_ping::PingIdentifier(rand::random());
        let mut pinger = client.pinger(ip.into(), identifier).await;
        let sequence = surge_ping::PingSequence(rand::random());
        match tokio::time::timeout(timeout, pinger.ping(sequence, &payload)).await {
            Ok(Ok((_, duration))) => Ok(duration.as_millis() as u64),
            Ok(Err(_)) => Ok(0),
            Err(_) => Ok(0)
        }
    }
}
