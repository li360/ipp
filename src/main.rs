use std::io::Write;
use std::sync::Arc;

pub mod chart;
pub mod cli;
pub mod ip_processor;

use clap::Parser;
use cli::Cli;
use colored::*;
use ip_processor::{IpInput, IpProcessor};
use ipnetwork::IpNetwork as ExternalIpNetwork;
use local_ip_address::Error as LocalIpError;
use std::clone::Clone;
use std::io::{stdout, IsTerminal};

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
use std::time::Duration;

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
    let network = if args.single {
        // 单IP模式不使用子网
        match &ip_input {
            IpInput::Single(ip) => ExternalIpNetwork::new(*ip, 32).unwrap(),
            _ => ExternalIpNetwork::new("0.0.0.0".parse().unwrap(), 24).unwrap(),
        }
    } else {
        match &ip_input {
            IpInput::Cidr(network) => *network,
            IpInput::Single(ip) => {
                // 对于单个IP，使用默认/24子网
                ExternalIpNetwork::new(*ip, 24).unwrap()
            }
            IpInput::Range((start, _)) => {
                // 对于范围IP，使用起始IP的/24子网
                ExternalIpNetwork::new(*start, 24).unwrap()
            }
        }
    };

    // 生成IP列表
    let ips = if args.single {
        match ip_input {
            IpInput::Single(ip) => vec![ip],
            _ => vec![],
        }
    } else {
        IpProcessor::generate_ips(ip_input.clone(), args.include_all, args.max_ips)
    };

    // 处理网络检测选项
    let results = if args.single {
        // 单IP模式强制使用IpInput::Single
        let ip = match ip_input {
            IpInput::Single(ip) => ip,
            IpInput::Cidr(network) => network.ip(),
            IpInput::Range((start, _)) => start,
        };

        // 如果指定了端口，优先进行端口测试
        if let Some(ports_str) = &args.port {
            println!("测试IP地址: {}", ip);
            let ports: Vec<u16> = ports_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let mut port_status = Vec::new();
            for port in ports {
            let mut total_latency = 0;
            let mut success_count = 0;
            
            for _i in 0..args.port_test_count {
                let latency = IpProcessor::check_port(
                    ip,
                    port,
                    Duration::from_millis(args.timeout)
                );
                
                    if let Some(latency_ms) = latency {
                        total_latency += latency_ms;
                        success_count += 1;
                        let chart = chart::LatencyChart::new(1000);
                        println!(
                            " {}",
                            chart.draw(Some(latency_ms))
                        );
                    } else {
                        let chart = chart::LatencyChart::new(1000);
                        println!(
                            " {}",
                            chart.draw(None)
                        );
                    }
                std::thread::sleep(Duration::from_millis(500)); // 添加500ms延迟
            }
            
            if success_count > 0 {
                let avg_latency = total_latency / success_count;
                println!(
                    "端口 {} 平均延迟: {}ms (成功次数: {}/{})",
                    port.to_string().green(),
                    avg_latency,
                    success_count,
                    args.port_test_count
                );
                port_status.push(Some(port));
            } else {
                println!(
                    "端口 {} 所有测试均失败",
                    port.to_string().red()
                );
                port_status.push(None);
            }
            }
            vec![(ip, port_status)]
        } else {
            // 没有指定端口时进行ping测试
            println!("测试单个IP地址: {}", ip);
            let mut all_timeout = true;
            for _i in 0..args.port_test_count {
                let result = IpProcessor::single_ip_test_once(ip, Duration::from_millis(args.timeout)).await;
                
                // 初始化图表
                let chart = chart::LatencyChart::new(1000); // 最大延迟1秒
                
                match result {
                    Ok(latency) if latency > 0 => {
                        all_timeout = false;
                        println!("{}", chart.draw(Some(latency)));
                    }
                    _ => {
                        println!("{}", chart.draw(None));
                    }
                }
                std::thread::sleep(Duration::from_millis(500)); // 添加500ms延迟
            }
            // 如果所有ping都超时，则不显示该IP
            if all_timeout {
                vec![]
            } else {
                vec![(ip, vec![Some(0)])]
            }
        }
    } else if let Some(ports_str) = &args.port {
        let ports: Vec<u16> = ports_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        if args.single {
            // 单IP模式进行端口测试
            let ip = match ip_input {
                IpInput::Single(ip) => ip,
                _ => {
                    eprintln!("{}", "单IP模式需要指定单个IP地址".red());
                    process::exit(1);
                }
            };
            println!("测试IP地址: {}", ip);
            let mut port_status = Vec::new();
            for port in ports {
                match tokio::time::timeout(
                    Duration::from_millis(args.timeout),
                    tokio::net::TcpStream::connect((ip, port)),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        println!("{}", format!("端口 {} 开放", port).green());
                        port_status.push(Some(port));
                    }
                    _ => {
                        println!("{}", format!("端口 {} 关闭", port).red());
                        port_status.push(None);
                    }
                }
            }
            vec![(ip, port_status)]
        } else {
            // 多IP模式进行端口测试
            let ports = Arc::new(ports);
            let port_results =
                    perform_port_tests(&ips, &ports, args.threads, args.timeout).await;
            let all_results = port_results;
            all_results
        }
    } else if !args.no_ping {
        // 默认超时时间设置为1ms
        let timeout = if args.timeout == 1000 {
            1
        } else {
            args.timeout
        };
        perform_ping_tests(&ips, args.no_retry, args.retries, args.threads, timeout).await
    } else {
        ips.iter().map(|&ip| (ip, vec![None])).collect()
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
            if !result.is_empty() && result.iter().any(|x| x.is_some()) {
                if count % args.width == 0 && count != 0 {
                    println!();
                }
                if stdout().is_terminal() {
                    print!("{} ", ip.to_string().green());
                } else {
                    print!("{} ", ip);
                }
                count += 1;
            }
        } else {
            // -a 参数时显示所有地址
            if count % args.width == 0 && count != 0 {
                println!();
            }
            if !result.is_empty() && result.iter().any(|x| x.is_some()) {
                if stdout().is_terminal() {
                    print!("{} ", ip.to_string().green());
                } else {
                    print!("{} ", ip);
                }
            } else {
                print!("{} ", ip);
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
    timeout: u64,
) -> Vec<(IpAddr, Vec<Option<u16>>)> {
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
            let result =
                match IpProcessor::single_ip_test_once(ip, Duration::from_millis(timeout)).await {
                    Ok(result) if result > 0 => (ip, vec![Some(result as u16)]),
                    _ => (ip, vec![None]),
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
    ports: &[u16],
    threads: usize,
    timeout: u64,
) -> Vec<(IpAddr, Vec<Option<u16>>)> {
    use futures::stream::StreamExt;
    use tokio::sync::Semaphore;

    let semaphore = Arc::new(Semaphore::new(threads));
    let mut results = Vec::with_capacity(ips.len());

    // 初始化结果向量，保持顺序
    for &ip in ips {
        results.push((ip, vec![None; ports.len()]));
    }

    let ports = Arc::new(ports.to_vec());
    let futures = ips.iter().enumerate().map(|(idx, &ip)| {
        let permit = semaphore.clone();
        let ports = Arc::clone(&ports);
        async move {
            let _permit = permit.acquire().await;

            // 使用tokio::join!同时测试多个端口
            let port_status = test_ports(ip, &ports, timeout).await;

            print!(".");
            std::io::stdout().flush().unwrap();
            (idx, port_status)
        }
    });

    let mut stream = futures::stream::iter(futures).buffer_unordered(threads);
    while let Some((idx, port_results)) = stream.next().await {
        results[idx].1 = port_results;
    }
    println!(); // 进度点后换行

    results
}

// 测试端口
async fn test_ports(ip: IpAddr, ports: &Arc<Vec<u16>>, timeout: u64) -> Vec<Option<u16>> {
    let mut handles = Vec::new();
    
    for port in ports.iter() {
        let ip = ip.clone();
        let port = *port;
        let handle = tokio::spawn(async move {
            let latency = IpProcessor::check_port(
                ip, 
                port, 
                Duration::from_millis(timeout)
            );
            
                    if let Some(latency_ms) = latency {
                        let chart = chart::LatencyChart::new(1000);
                        println!(
                            "{} 端口 {} 开放 (延迟: {}ms)",
                            chart.draw(Some(latency_ms)),
                            port.to_string().green(),
                            latency_ms
                        );
                        Some(port)
                    } else {
                        let chart = chart::LatencyChart::new(1000);
                        println!(
                            "{} 端口 {} 关闭",
                            chart.draw(None),
                            port.to_string().red()
                        );
                        None
                    }
        });
        handles.push(handle);
    }
    
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    
    results
}

// 获取本地IP地址
fn get_local_ip() -> Result<String, IpProcessorError> {
    use ipnetwork::IpNetwork as ExternalIpNetwork;
    use local_ip_address::local_ip;

    let ip = local_ip()?;
    let network = ExternalIpNetwork::new(ip, 24)?; // 默认使用/24子网掩码
    Ok(network.to_string())
}
