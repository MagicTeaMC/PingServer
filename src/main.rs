#![feature(ip)]
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use std::process::Command;

#[derive(Deserialize)]
struct PingRequest {
    api_key: String,
    target: String,  // Changed from target_ip to target to be more generic
    ip_version: String,
}

#[derive(Deserialize)]
struct MtrRequest {
    api_key: String,
    target: String,  // Changed from target_ip to target to be more generic
    ip_version: String,
}

#[derive(Serialize)]
struct PingResponse {
    success: bool,
    output: String,
}

#[derive(Serialize)]
struct MtrResponse {
    success: bool,
    output: String,
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_unique_local() || ipv6.is_loopback() || ipv6.is_multicast(),
    }
}

fn load_api_keys() -> Vec<String> {
    dotenv().ok();
    let keys = env::var("API_KEYS").unwrap_or_default();
    keys.split(',').map(|s| s.to_string()).collect()
}

fn is_valid_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.'
}

fn is_valid_domain_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    
    // Label cannot start or end with hyphen
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    
    // All characters must be valid
    label.chars().all(is_valid_domain_char)
}

fn validate_domain(domain: &str) -> Result<(), String> {
    // Basic length check
    if domain.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }
    
    if domain.len() > 253 {
        return Err("Domain name too long (max 253 characters)".to_string());
    }
    
    // Remove trailing dot if present (FQDN)
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    
    // Check for invalid characters
    if !domain.chars().all(is_valid_domain_char) {
        return Err("Domain contains invalid characters".to_string());
    }
    
    // Cannot start or end with dot or hyphen
    if domain.starts_with('.') || domain.ends_with('.') || 
       domain.starts_with('-') || domain.ends_with('-') {
        return Err("Domain has invalid format".to_string());
    }
    
    // Cannot have consecutive dots
    if domain.contains("..") {
        return Err("Domain cannot contain consecutive dots".to_string());
    }
    
    // Split into labels and validate each
    let labels: Vec<&str> = domain.split('.').collect();
    
    if labels.len() < 2 {
        return Err("Domain must have at least two labels (e.g., example.com)".to_string());
    }
    
    for label in &labels {
        if !is_valid_domain_label(label) {
            return Err(format!("Invalid domain label: '{}'", label));
        }
    }
    
    // Check for blocked domains/patterns
    let domain_lower = domain.to_lowercase();
    
    // Block localhost and local domains
    if domain_lower == "localhost" || domain_lower.ends_with(".localhost") ||
       domain_lower.ends_with(".local") || domain_lower.ends_with(".localdomain") {
        return Err("Local domains are not allowed".to_string());
    }
    
    // Block internal/private domains
    if domain_lower.ends_with(".internal") || domain_lower.ends_with(".corp") ||
       domain_lower.ends_with(".home") || domain_lower.ends_with(".lan") {
        return Err("Internal/private domains are not allowed".to_string());
    }
    
    // Block test domains
    if domain_lower.ends_with(".test") || domain_lower.ends_with(".example") {
        return Err("Test/example domains are not allowed".to_string());
    }
    
    // Block domains that resolve to private IPs (basic patterns)
    if domain_lower.contains("10.") || domain_lower.contains("192.168.") ||
       domain_lower.contains("172.16.") || domain_lower.contains("127.") {
        return Err("Domains containing private IP patterns are not allowed".to_string());
    }
    
    Ok(())
}

fn validate_target(target: &str) -> Result<(), String> {
    // Trim whitespace
    let target = target.trim();
    
    if target.is_empty() {
        return Err("Target cannot be empty".to_string());
    }
    
    // Try to parse as IP address
    if let Ok(ip_addr) = target.parse::<IpAddr>() {
        // If it's an IP, check if it's private
        if is_private_ip(ip_addr) {
            return Err("Private network IP addresses are not allowed".to_string());
        }
    } else {
        // If it's not an IP, validate as domain
        validate_domain(target)?;
    }
    
    Ok(())
}

fn execute_ping(target: &str, ip_version_flag: &str) -> Result<String, String> {
    let mut cmd = Command::new("ping");
    
    // Add IP version flag if specified
    if ip_version_flag == "-4" {
        cmd.arg("-4");
    } else if ip_version_flag == "-6" {
        cmd.arg("-6");
    }
    
    let output = cmd
        .arg("-c")
        .arg("4")
        .arg(target)  // Pass target directly (IP or domain)
        .output()
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    let stdout_result = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_result = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout_result.is_empty() && !stderr_result.is_empty() {
        return Err(format!("Ping command failed with error: {}", stderr_result));
    }

    Ok(stdout_result)
}

fn execute_mtr(target: &str, ip_version_flag: &str) -> Result<String, String> {
    let mut cmd = Command::new("mtr");
    
    // Add IP version flag if specified
    if ip_version_flag == "-4" {
        cmd.arg("-4");
    } else if ip_version_flag == "-6" {
        cmd.arg("-6");
    }
    
    let output = cmd
        .arg("--report")
        .arg("--report-cycles")
        .arg("10")
        .arg(target)
        .output()
        .map_err(|e| format!("Failed to execute mtr: {}", e))?;

    let stdout_result = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_result = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout_result.is_empty() && !stderr_result.is_empty() {
        return Err(format!("MTR command failed with error: {}", stderr_result));
    }

    Ok(stdout_result)
}

#[post("/ping")]
async fn ping(req: web::Json<PingRequest>) -> impl Responder {
    let valid_api_keys = load_api_keys();
    if !valid_api_keys.contains(&req.api_key) {
        return HttpResponse::Unauthorized().json(PingResponse {
            success: false,
            output: "Invalid API key".to_string(),
        });
    }

    // Validate target (IP or domain)
    if let Err(error) = validate_target(&req.target) {
        return HttpResponse::Forbidden().json(PingResponse {
            success: false,
            output: error,
        });
    }

    let ip_version_flag = match req.ip_version.as_str() {
        "ipv4" => "-4",
        "ipv6" => "-6",
        "auto" | "" => "",  // Let ping decide
        _ => {
            return HttpResponse::BadRequest().json(PingResponse {
                success: false,
                output: "Invalid IP version. Use 'ipv4', 'ipv6', or 'auto'".to_string(),
            });
        }
    };

    match execute_ping(&req.target, ip_version_flag) {
        Ok(output) => HttpResponse::Ok().json(PingResponse {
            success: true,
            output,
        }),
        Err(error) => HttpResponse::InternalServerError().json(PingResponse {
            success: false,
            output: error,
        }),
    }
}

#[post("/mtr")]
async fn mtr(req: web::Json<MtrRequest>) -> impl Responder {
    let valid_api_keys = load_api_keys();
    if !valid_api_keys.contains(&req.api_key) {
        return HttpResponse::Unauthorized().json(MtrResponse {
            success: false,
            output: "Invalid API key".to_string(),
        });
    }

    // Validate target (IP or domain)
    if let Err(error) = validate_target(&req.target) {
        return HttpResponse::Forbidden().json(MtrResponse {
            success: false,
            output: error,
        });
    }

    let ip_version_flag = match req.ip_version.as_str() {
        "ipv4" => "-4",
        "ipv6" => "-6",
        "auto" | "" => "",  // Let mtr decide
        _ => {
            return HttpResponse::BadRequest().json(MtrResponse {
                success: false,
                output: "Invalid IP version. Use 'ipv4', 'ipv6', or 'auto'".to_string(),
            });
        }
    };

    match execute_mtr(&req.target, ip_version_flag) {
        Ok(output) => HttpResponse::Ok().json(MtrResponse {
            success: true,
            output,
        }),
        Err(error) => HttpResponse::InternalServerError().json(MtrResponse {
            success: false,
            output: error,
        }),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(ping)
            .service(mtr)
    })
    .bind("0.0.0.0:9199")?
    .run()
    .await
}