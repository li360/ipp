use std::cmp::max;
use colored::*;

const MAX_CHART_WIDTH: usize = 80;
const TIMEOUT_SYMBOL: &str = "✖";

pub struct LatencyChart {
    max_latency: u64,
    chart_width: usize,
}

impl LatencyChart {
    pub fn new(max_latency: u64) -> Self {
        let terminal_width = term_size::dimensions()
            .map(|(w, _)| w)
            .unwrap_or(MAX_CHART_WIDTH);
        
        // 保留20字符用于数值显示
        let chart_width = max(20, terminal_width - 20).min(MAX_CHART_WIDTH);

        Self {
            max_latency,
            chart_width,
        }
    }

    pub fn draw(&self, latency: Option<u64>) -> String {
        match latency {
            Some(latency) => {
                let bar_width = (latency as f64 / self.max_latency as f64 * self.chart_width as f64) as usize;
                // 确保最小显示1个字符
                let bar_width = bar_width.max(1);
                let bar = "▇".repeat(bar_width).green();
                format!("{} {:>4}ms", bar, latency)
            }
            None => {
                let bar = TIMEOUT_SYMBOL.repeat(self.chart_width).red();
                format!("{} {:>6}", bar, "超时".red())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chart_drawing() {
        let chart = LatencyChart::new(100);
        
        // 测试正常延迟
        let result = chart.draw(Some(50));
        assert!(result.contains("50ms"));
        
        // 测试超时
        let result = chart.draw(None);
        assert!(result.contains("超时"));
    }
}
