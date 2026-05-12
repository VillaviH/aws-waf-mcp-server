# aws-waf-logs MCP Server

An MCP (Model Context Protocol) server that lets any AI agent — Claude, Amazon Q, Kiro IDE, Cursor — analyze AWS WAF logs, detect attacks, and generate interactive HTML reports, all through natural language.

> 📖 **Article:** [aws-waf-logs MCP Server: Analyze Your WAF Logs with AI](./article-builder-center-en.html) — Published on AWS Builder Center

---

## ✨ Features

- 📊 Full day analysis with consolidated stats (traffic, rules, countries, domains)
- 🚨 Attack pattern detection: `.env`, `.git`, path traversal, SQL injection, webshells, and more
- �� Forensic investigation by IP, URI pattern, or WAF rule
- ☁️ Direct S3 download — full day logs with hourly structure
- 📄 Interactive HTML report with Chart.js graphs
- ⏱️ Hourly traffic breakdown to identify attack spikes

## 🛠️ Tools (11 total)

| Tool | Description |
|------|-------------|
| `analyze_waf_logs` | Analyze a single log file (.gz or .json) |
| `analyze_full_day` | Analyze all files in a directory (full day) |
| `detect_attacks` | Detect known attack patterns |
| `get_blocked_requests` | List blocked requests with full details |
| `search_by_ip` | Find all requests from a specific IP |
| `search_by_uri` | Search requests by URI pattern |
| `get_rule_details` | Show all requests blocked by a specific rule |
| `get_hourly_breakdown` | Traffic and blocks breakdown by hour |
| `generate_html_report` | Generate interactive HTML report |
| `download_waf_logs_from_s3` | Download logs from any S3 bucket |
| `download_day_logs` | Download a full day of logs from S3 |

## 🚀 Installation

```bash
git clone https://github.com/YOUR_USERNAME/aws-waf-mcp-server.git
cd aws-waf-mcp-server
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## ⚙️ Configuration

Add to your MCP client config (`.kiro/settings/mcp.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcpServers": {
    "aws-waf-logs": {
      "command": "/full/path/to/aws-waf-mcp-server/venv/bin/python3",
      "args": ["/full/path/to/aws-waf-mcp-server/server.py"],
      "env": {
        "AWS_PROFILE": "default",
        "AWS_REGION": "us-east-1"
      },
      "disabled": false,
      "autoApprove": [
        "analyze_waf_logs",
        "get_blocked_requests",
        "search_by_ip",
        "search_by_uri",
        "get_rule_details"
      ]
    }
  }
}
```

## 🔐 Required AWS Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-waf-logs-bucket",
        "arn:aws:s3:::your-waf-logs-bucket/*"
      ]
    }
  ]
}
```

## 💬 Example Usage

Once configured, just ask your AI assistant:

```
"Download WAF logs from May 7, 2026 and give me a summary"
"What attack patterns were detected today?"
"Investigate IP 196.207.45.123 — what is it doing?"
"Generate an HTML report for the security team"
"Show me the hourly traffic breakdown"
"Which WAF rule blocked the most requests?"
```

## 📊 Real Results (May 7, 2026)

| Metric | Value |
|--------|-------|
| Total requests | 109,290 |
| Allowed | 105,837 (96.8%) |
| Blocked | 1,941 (1.78%) |
| .env attempts | 839 (775 allowed ⚠️) |
| Top blocking rule | AWS-AWSManagedRulesBotControlRuleSet |
| Top blocked country | Mauritius (839 blocks) |

## 🧰 Built With

- [FastMCP](https://github.com/jlowin/fastmcp) — MCP server framework for Python
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK for Python
- [Model Context Protocol](https://modelcontextprotocol.io) — Open standard by Anthropic

## 📄 License

MIT License — see [LICENSE](./LICENSE) for details.

---

*Built by [Hernán Villavicencio](https://github.com/YOUR_USERNAME) · AWS Community Builder · Cloud Security*
