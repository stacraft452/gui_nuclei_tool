import json
import os

CATEGORY_JSON = os.path.join(os.path.dirname(__file__), "category_groups.json")

DEFAULT_CATEGORY_GROUPS = {
    "Web漏洞测试": [
        "apache", "api", "atlassian", "auth", "backup", "cpanel", "crlf_injection",
        "cross_site_request_forgery", "cve", "dast", "debug", "default", "directory_listing",
        "docker", "drupal", "exposed", "favicon", "file", "ftp", "fuzz", "git", "graphql",
        "header", "http", "injection", "java", "javascript", "jenkins", "joomla", "laravel",
        "ldap", "local_file_inclusion", "magento", "microsoft", "mongodb", "mysql", "nginx",
        "nodejs", "open_redirect", "oracle", "perl", "php", "postgres", "python", "redis",
        "remote_code_execution", "ruby", "samba", "sap", "sensitive", "sharepoint", "shopify",
        "smtp", "sql", "sql_injection", "ssh", "ssl", "ssrf", "subdomain_takeover",
        "template_injection", "upload", "vmware", "web", "wordpress", "workflows",
        "xml_external_entity", "xss"
    ],
    "云安全测试": [
        "aws", "cloud", "gcloud", "netlify"
    ],
    "网络设备/基础设施安全": [
        "cisco", "dns", "elk", "ibm", "kafka", "kong", "network", "rabbitmq"
    ],
    "漏洞情报/合规": [
        "cnnvd", "cnvd"
    ],
    "其他/辅助/通用": [
        "adobe", "airflow", "code", "coldfusion", "config", "detect", "extract", "google",
        "graphite", "headless", "helpers", "other", "passive", "profiles", "search", "social"
    ]
}

def load_category_groups():
    if os.path.exists(CATEGORY_JSON):
        with open(CATEGORY_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        return DEFAULT_CATEGORY_GROUPS.copy()

def save_category_groups(groups):
    with open(CATEGORY_JSON, "w", encoding="utf-8") as f:
        json.dump(groups, f, ensure_ascii=False, indent=2)
