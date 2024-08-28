#![feature(ip)]
use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

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

const API_KEY: &str = "your_api_key";

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

#[post("/ping")]
async fn ping(req: web::Json<PingRequest>) -> impl Responder {
    if req.api_key != API_KEY {
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
            let result = String::from_utf8_lossy(&output.stdout).to_string();
            HttpResponse::Ok().json(PingResponse {
                success: true,
                output: result,
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
