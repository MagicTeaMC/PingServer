#![feature(ip)]
use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::env;
use dotenvy::dotenv;

#[derive(Deserialize)]
struct PingRequest {
    api_key: String,
    target_ip: String,
    ip_version: String,
}

#[derive(Serialize)]
struct PingResponse {
    success: bool,
    output: String,
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_unique_local() || ipv6.is_loopback() || ipv6.is_multicast()
        }
    }
}

fn load_api_keys() -> Vec<String> {
    dotenv().ok();
    let keys = env::var("API_KEYS").unwrap_or_default();
    keys.split(',').map(|s| s.to_string()).collect()
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

let output = Command::new("ping")
    .arg(ip_version_flag)
    .arg("-c")
    .arg("4")
    .arg(ip_addr.to_string())
    .output();

match output {
    Ok(output) => {
        let stdout_result = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr_result = String::from_utf8_lossy(&output.stderr).to_string();
        
            if stdout_result.is_empty() && !stderr_result.is_empty() {
               return HttpResponse::InternalServerError().json(PingResponse {
                   success: false,
                   output: format!("Ping command failed with error: {}", stderr_result),
             });
           }

          HttpResponse::Ok().json(PingResponse {
                success: true,
                output: stdout_result,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(PingResponse {
            success: false,
            output: format!("Failed to execute ping: {}", e),
        }),
    }

}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(ping)
    })
    .bind("0.0.0.0:9199")?
    .run()
    .await
}
