import os
import json
import webbrowser
import datetime
from jinja2 import Template

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.template_str = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sıfır Güven (Zero Trust) Tünel Raporu</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #58a6ff; margin: 0; }
        .summary-dashboard { display: flex; gap: 20px; margin-bottom: 40px; }
        .stat-card { flex: 1; background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-card h3 { margin: 0 0 10px 0; color: #8b949e; font-size: 14px; text-transform: uppercase; }
        .stat-card .value { font-size: 36px; font-weight: bold; }
        .val-critical { color: #f85149; }
        .val-warning { color: #d29922; }
        .val-info { color: #58a6ff; }
        .val-success { color: #2ea043; }
        
        .finding-section { margin-bottom: 30px; }
        .finding-section h2 { color: #e6edf3; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        
        .finding-card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }
        .finding-header { padding: 12px 20px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
        .finding-header.Semgrep { background-color: rgba(46, 160, 67, 0.15); border-left: 4px solid #2ea043; }
        .finding-header.Detect-Secrets { background-color: rgba(248, 81, 73, 0.15); border-left: 4px solid #f85149; }
        .finding-header.OSV-Scanner { background-color: rgba(210, 153, 34, 0.15); border-left: 4px solid #d29922; }
        .finding-body { padding: 20px; }
        .finding-body p { margin: 0 0 10px 0; }
        .code-snippet { background-color: #010409; border: 1px solid #30363d; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; color: #e6edf3; }
        .file-path { color: #58a6ff; font-family: monospace; }
        
        .empty-state { text-align: center; padding: 50px; background-color: #161b22; border-radius: 8px; border: 1px dashed #2ea043; color: #2ea043; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Sıfır Güven (Zero Trust) Tünel Raporu</h1>
            <p>Tarama Tarihi: {{ date }} | Hedef: <span class="file-path">{{ target }}</span></p>
        </div>

        <div class="summary-dashboard">
            <div class="stat-card">
                <h3>Mantık & Enjeksiyon Hataları</h3>
                <div class="value val-info">{{ semgrep_count }}</div>
            </div>
            <div class="stat-card">
                <h3>Kritik Sızıntılar (Şifreler)</h3>
                <div class="value val-critical">{{ secrets_count }}</div>
            </div>
            <div class="stat-card">
                <h3>Zafiyetli Kütüphaneler (CVE)</h3>
                <div class="value val-warning">{{ osv_count }}</div>
            </div>
        </div>

        <div class="finding-section">
            <h2>Detaylı Analiz Sonuçları</h2>
            
            {% if total_count == 0 %}
            <div class="empty-state">
                <h2>%100 Güvenli!</h2>
                <p>Bu kod bloğunda hiçbir sözdizimi hatası, sızıntı veya zafiyetli kütüphane bulunamadı. Tünelden başarıyla geçti.</p>
            </div>
            {% else %}
                
                {% for issue in findings %}
                <div class="finding-card">
                    <div class="finding-header {{ issue.engine }}">
                        <span>[{{ issue.engine }}] {{ issue.title }}</span>
                        <span>Satır: {{ issue.line }}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Dosya:</strong> <span class="file-path">{{ issue.file }}</span></p>
                        <p><strong>Açıklama:</strong> {{ issue.description }}</p>
                        {% if issue.code %}
                        <div class="code-snippet">{{ issue.code }}</div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

    def parse_semgrep(self, stdout):
        findings = []
        try:
            data = json.loads(stdout)
            for result in data.get('results', []):
                findings.append({
                    "engine": "Semgrep",
                    "title": result.get('check_id', 'Genel Hata'),
                    "file": result.get('path', 'Bilinmeyen Dosya'),
                    "line": result.get('start', {}).get('line', 'N/A'),
                    "description": result.get('extra', {}).get('message', ''),
                    "code": result.get('extra', {}).get('lines', '')
                })
        except:
            pass
        return findings

    def parse_detect_secrets(self, stdout):
        findings = []
        try:
            data = json.loads(stdout)
            for filepath, secrets in data.get('results', {}).items():
                for secret in secrets:
                    findings.append({
                        "engine": "Detect-Secrets",
                        "title": secret.get('type', 'Bilinmeyen Sır'),
                        "file": filepath,
                        "line": secret.get('line_number', 'N/A'),
                        "description": "Kritik bir şifre veya kimlik bilgisi bulundu. (Yüksek Entropi)",
                        "code": ""
                    })
        except:
            pass
        return findings

    def parse_osv(self, stdout):
        findings = []
        try:
            data = json.loads(stdout)
            for result in data.get('results', []):
                source = result.get('source', {}).get('path', 'Bilinmeyen Dosya')
                for package in result.get('packages', []):
                    pkg_info = package.get('package', {})
                    pkg_name = pkg_info.get('name', 'Bilinmeyen')
                    pkg_version = pkg_info.get('version', 'Bilinmeyen')
                    
                    for vuln in package.get('vulnerabilities', []):
                        findings.append({
                            "engine": "OSV-Scanner",
                            "title": f"CVE: {vuln.get('id', 'N/A')} - {pkg_name} ({pkg_version})",
                            "file": source,
                            "line": "Paket Dosyası",
                            "description": vuln.get('summary', vuln.get('details', 'Zafiyetli kütüphane tespit edildi.')),
                            "code": ""
                        })
        except:
            pass
        return findings

    def generate_report(self, target_path, semgrep_out, secrets_out, osv_out):
        semgrep_findings = self.parse_semgrep(semgrep_out)
        secrets_findings = self.parse_detect_secrets(secrets_out)
        osv_findings = self.parse_osv(osv_out)
        
        all_findings = semgrep_findings + secrets_findings + osv_findings
        
        template = Template(self.template_str)
        html_content = template.render(
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=target_path,
            semgrep_count=len(semgrep_findings),
            secrets_count=len(secrets_findings),
            osv_count=len(osv_findings),
            total_count=len(all_findings),
            findings=all_findings
        )
        
        report_path = os.path.join(self.output_dir, f"Tunel_Raporu_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        # Raporu tarayıcıda otomatik aç
        webbrowser.open(f"file:///{os.path.abspath(report_path)}")
        return report_path
