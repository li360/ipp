use ipnetwork::{IpNetwork as ExternalIpNetwork, IpNetworkError};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug)]
pub enum IpInput {
    Single(IpAddr),
    Cidr(ExternalIpNetwork),
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

    pub fn generate_ips(
        input: IpInput,
        include_all: bool,
        max_ips: usize,
    ) -> Vec<IpAddr> {
        match input {
            IpInput::Single(ip) => vec![ip],
            IpInput::Cidr(network) => {
                Self::generate_cidr_ips(network, include_all, max_ips)
            }
            IpInput::Range((start, end)) => {
                Self::generate_range_ips(start, end, max_ips)
            }
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

    fn generate_range_ips(
        start: IpAddr,
        end: IpAddr,
        max_ips: usize,
    ) -> Vec<IpAddr> {
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

    pub fn check_port(ip: IpAddr, port: u16, timeout: Duration) -> bool {
        match TcpStream::connect_timeout(&(ip, port).into(), timeout) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
