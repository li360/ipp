use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ipp", version = env!("CARGO_PKG_VERSION"))]
#[command(about = "IP地址处理工具", long_about = "支持以下IP格式：
  1. 单个IP：192.168.1.1
  2. CIDR格式：192.168.1.0/24
  3. IP范围：192.168.1.1-10
  4. 本地IP：不指定输入时自动获取")]
pub struct Cli {
    /// 输入IP地址（单个IP、CIDR或范围）
    #[arg(required = false)]
    pub input: Option<String>,

    /// 包含网络地址和广播地址
    #[arg(short = 'a', long = "all")]
    pub include_all: bool,

    /// 最大输出IP数量
    #[arg(short = 'm', long = "max", default_value_t = 1000)]
    pub max_ips: usize,

    /// 每行输出的IP数量
    #[arg(short = 'w', long = "width", default_value_t = 5)]
    pub width: usize,

    /// 禁用对生成IP的ping测试
    #[arg(long = "no-ping")]
    pub no_ping: bool,

    /// 禁用ping重试以加快执行速度
    #[arg(short = 'n', long = "no-retry")]
    pub no_retry: bool,

    /// ping重试次数（0表示不重试）
    #[arg(short = 'r', long = "retries", default_value_t = 0)]
    pub retries: u32,

    /// 最大并发ping线程数
    #[arg(short = 't', long = "threads", default_value_t = 100)]
    pub threads: usize,

    /// ping超时时间（毫秒）
    #[arg(short = 'o', long = "timeout", default_value_t = 1000)]
    pub timeout: u64,

    /// 使用端口检测代替ping测试
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,
}
