use std::sync::Arc;
use std::io::Write;

pub mod cli;
pub mod ip_processor;

use clap::Parser;
use cli::Cli;
use colored::*;
use ip_processor::{IpProcessor, IpInput};
use ipnetwork::IpNetwork as ExternalIpNetwork;
use local_ip_address::Error as LocalIpError;

// 定义IP处理器错误类型
#[derive(Debug)]
pub enum IpProcessorError {
    Io(std::io::Error),
    AddrParse(std::net::AddrParseError),
    IpNetwork(ipnetwork::IpNetworkError),
    LocalIp(LocalIpError),
}

// 实现错误类型转换
impl From<std::io::Error> for IpProcessorError {
    fn from(err: std::io::Error) -> Self {
        IpProcessorError::Io(err)
    }
}

impl From<std::net::AddrParseError> for IpProcessorError {
    fn from(err: std::net::AddrParseError) -> Self {
        IpProcessorError::AddrParse(err)
    }
}

impl From<ipnetwork::IpNetworkError> for IpProcessorError {
    fn from(err: ipnetwork::IpNetworkError) -> Self {
        IpProcessorError::IpNetwork(err)
    }
}

impl From<LocalIpError> for IpProcessorError {
    fn from(err: LocalIpError) -> Self {
        IpProcessorError::LocalIp(err)
    }
}

use std::net::IpAddr;
use std::process;

// 主函数
#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = Cli::parse();

    // 如果没有提供输入IP，则获取本地IP
    let input = match args.input {
        Some(input) => input,
        None => {
            if let Ok(local_ip) = get_local_ip() {
                local_ip
            } else {
                eprintln!("{}", "获取本地IP地址失败".red());
                process::exit(1);
            }
        }
    };

    // 解析输入IP
    let ip_input = match IpProcessor::parse_input(&input) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("{}: {:?}", "无效的IP输入".red(), e);
            process::exit(1);
        }
    };

    // 获取网络信息
    let network = match &ip_input {
        IpInput::Cidr(network) => *network,
        IpInput::Single(ip) => {
            // 对于单个IP，使用默认/24子网
            ExternalIpNetwork::new(*ip, 24).unwrap()
        }
        IpInput::Range(_) => {
            eprintln!("{}", "范围IP地址需要指定CIDR格式".red());
            process::exit(1);
        }
    };

    // 生成IP列表
    let ips = IpProcessor::generate_ips(ip_input, args.include_all, args.max_ips);

    // 处理网络检测选项
    let results = if let Some(port) = args.port {
        perform_port_tests(&ips, port, args.threads, args.timeout).await
    } else if !args.no_ping {
        // 默认超时时间设置为1ms
        let timeout = if args.timeout == 1000 { 1 } else { args.timeout };
        perform_ping_tests(&ips, args.no_retry, args.retries, args.threads, timeout).await
    } else {
        ips.iter().map(|&ip| (ip, None)).collect()
    };

    // 控制输出宽度打印结果
    let mut count = 0;
    for (ip, result) in results {
        // 跳过网络地址和广播地址
        if let IpAddr::V4(ipv4) = ip {
            if IpProcessor::is_network_address(IpAddr::V4(ipv4), network) || ipv4.is_broadcast() {
                continue;
            }
        }
        
        // 无参数时只显示可ping通的地址
        if !args.include_all {
            if let Some(_) = result {
                if count % args.width == 0 && count != 0 {
                    println!();
                }
                print!("{} ", ip.to_string().green());
                count += 1;
            }
        } else {
            // -a 参数时显示所有地址
            if count % args.width == 0 && count != 0 {
                println!();
            }
            match result {
                Some(_) => print!("{} ", ip.to_string().green()),
                None => print!("{} ", ip),
            }
            count += 1;
        }
    }
    if count > 0 {
        println!();
    }
}

// 执行ping测试
async fn perform_ping_tests(
    ips: &[IpAddr], 
    no_retry: bool, 
    retries: u32, 
    threads: usize,
    timeout: u64
) -> Vec<(IpAddr, Option<()>)> {
    use futures::stream::StreamExt;
    use tokio::sync::Semaphore;
    
    // 使用信号量限制并发ping数量
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut results = Vec::new();
    
    // 创建future流
    let futures = ips.iter().map(|&ip| {
        let permit = semaphore.clone();
        async move {
            let _permit = permit.acquire().await;
            use std::time::Duration;
            let _retries = if no_retry { 0 } else { retries };
            let result = match ping::ping(
                ip, 
                Some(Duration::from_millis(timeout)), 
                None, 
                Some(if no_retry { 0 } else { 1 }), // 最多重试1次
                None, 
                None
            ) {
                Ok(reply) => (ip, Some(reply)),
                Err(_) => (ip, None),
            };
            // 打印进度
            print!(".");
            std::io::stdout().flush().unwrap();
            result
        }
    });

    // 使用线程参数并行处理
    let mut stream = futures::stream::iter(futures).buffer_unordered(threads);
    while let Some(result) = stream.next().await {
        results.push(result);
    }
    println!(); // 进度点后换行
    
    results
}

// 执行端口检测
async fn perform_port_tests(
    ips: &[IpAddr],
    port: u16,
    threads: usize,
    timeout: u64
) -> Vec<(IpAddr, Option<()>)> {
    use futures::stream::StreamExt;
    use tokio::sync::Semaphore;
    use tokio::time::Duration;
    
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut results = Vec::with_capacity(ips.len());
    
    // 初始化结果向量，保持顺序
    for &ip in ips {
        results.push((ip, None));
    }

    let futures = ips.iter().enumerate().map(|(idx, &ip)| {
        let permit = semaphore.clone();
        async move {
            let _permit = permit.acquire().await;
            let result = match tokio::time::timeout(
                Duration::from_millis(timeout),
                tokio::net::TcpStream::connect((ip, port))
            ).await {
                Ok(Ok(_)) => Some(()),
                _ => None,
            };
            print!(".");
            std::io::stdout().flush().unwrap();
            (idx, result)
        }
    });

    let mut stream = futures::stream::iter(futures).buffer_unordered(threads);
    while let Some((idx, result)) = stream.next().await {
        results[idx].1 = result;
    }
    println!(); // 进度点后换行
    
    results
}

// 获取本地IP地址
fn get_local_ip() -> Result<String, IpProcessorError> {
    use local_ip_address::local_ip;
    use ipnetwork::IpNetwork as ExternalIpNetwork;
    
    let ip = local_ip()?;
    let network = ExternalIpNetwork::new(ip, 24)?; // 默认使用/24子网掩码
    Ok(network.to_string())
}
