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
    target_ip: String,
    ip_version: String,
}

#[derive(Deserialize)]
struct MtrRequest {
    api_key: String,
    target_ip: String,
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

fn execute_ping(ip_addr: &IpAddr, ip_version_flag: &str) -> Result<String, String> {
    let output = Command::new("ping")
        .arg(ip_version_flag)
        .arg("-c")
        .arg("4")
        .arg(ip_addr.to_string())
        .output()
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    let stdout_result = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_result = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout_result.is_empty() && !stderr_result.is_empty() {
        return Err(format!("Ping command failed with error: {}", stderr_result));
    }

    Ok(stdout_result)
}

fn execute_mtr(ip_addr: &IpAddr, ip_version_flag: &str) -> Result<String, String> {
    let mut cmd = Command::new("mtr");
    
    // Add IP version flag
    if ip_version_flag == "-4" {
        cmd.arg("-4");
    } else if ip_version_flag == "-6" {
        cmd.arg("-6");
    }
    
    let output = cmd
        .arg("--report")           // Generate report instead of interactive mode
        .arg("--report-cycles")    // Number of pings per hop
        .arg("10")
        .arg("--no-dns")          // Don't resolve hostnames (faster and more reliable)
        .arg(ip_addr.to_string())
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

    let ip_addr: IpAddr = match req.target_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(PingResponse {
                success: false,
                output: "Invalid IP address".to_string(),
            });
        }
    };

    if is_private_ip(ip_addr) {
        return HttpResponse::Forbidden().json(PingResponse {
            success: false,
            output: "Pinging private network IP addresses is not allowed".to_string(),
        });
    }

    let ip_version_flag = match req.ip_version.as_str() {
        "ipv4" => "-4",
        "ipv6" => "-6",
        _ => {
            return HttpResponse::BadRequest().json(PingResponse {
                success: false,
                output: "Invalid IP version".to_string(),
            });
        }
    };

    match execute_ping(&ip_addr, ip_version_flag) {
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

    let ip_addr: IpAddr = match req.target_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(MtrResponse {
                success: false,
                output: "Invalid IP address".to_string(),
            });
        }
    };

    if is_private_ip(ip_addr) {
        return HttpResponse::Forbidden().json(MtrResponse {
            success: false,
            output: "MTR to private network IP addresses is not allowed".to_string(),
        });
    }

    let ip_version_flag = match req.ip_version.as_str() {
        "ipv4" => "-4",
        "ipv6" => "-6",
        _ => {
            return HttpResponse::BadRequest().json(MtrResponse {
                success: false,
                output: "Invalid IP version".to_string(),
            });
        }
    };

    match execute_mtr(&ip_addr, ip_version_flag) {
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