use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Error as PcapError};
use redis::Connection;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PacketLog {
    src_ip: String,
    dst_ip: String,
    protocol: String,
    src_port: u16,
    dst_port: u16,
    risk_score: u8,
    length: u32,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FirewallAction {
    BlockIp,
    Quarantine,
    Escalate,
}

#[derive(Debug, Deserialize)]
struct FirewallCommand {
    command_id: Option<String>,
    action: FirewallAction,
    target_ip: String,
    site: Option<String>,
    segment: Option<String>,
    reason: Option<String>,
    requested_at: Option<String>,
}

struct RedisPublisher {
    client: redis::Client,
    connection: Option<Connection>,
}

impl RedisPublisher {
    fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            connection: None,
        })
    }

    fn connect(&mut self) -> Result<(), redis::RedisError> {
        let connection = self.client.get_connection()?;
        self.connection = Some(connection);
        Ok(())
    }

    fn publish(&mut self, channel: &str, payload: &str) -> Result<(), redis::RedisError> {
        if self.connection.is_none() {
            self.connect()?;
        }

        let Some(connection) = self.connection.as_mut() else {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "Redis connection missing",
            )));
        };

        let publish_result: redis::RedisResult<i32> =
            redis::cmd("PUBLISH").arg(channel).arg(payload).query(connection);

        match publish_result {
            Ok(_) => Ok(()),
            Err(err) => {
                self.connection = None;
                Err(err)
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("PacketPrism :: Live Transport + Control Plane");

    if let Ok(ip) = local_ip_address::local_ip() {
        println!("Local IP: {ip}");
    }

    let device = select_default_device()?;
    let device_name = device.name.clone();
    println!("Selected interface: {device_name}");
    println!("Promiscuous mode: enabled");
    println!("Press Ctrl+C to stop.\n");

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })?;
    }

    let mut capture = open_capture(device).map_err(map_open_error)?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let _listener = start_firewall_listener(redis_url.clone());

    let mut publisher = RedisPublisher::new(&redis_url)?;
    if let Err(err) = publisher.connect() {
        eprintln!("Connection Lost: {err}. Retrying...");
    }

    let mut total_packets: u64 = 0;
    let mut emitted_logs: u64 = 0;
    let mut published_logs: u64 = 0;

    while running.load(Ordering::SeqCst) {
        match capture.next_packet() {
            Ok(packet) => {
                total_packets += 1;
                if let Some(log) = packet_to_log(packet.data, packet.header.len) {
                    match serde_json::to_string(&log) {
                        Ok(json) => {
                            emitted_logs += 1;
                            if let Err(err) = publisher.publish("packet_stream", &json) {
                                eprintln!("Connection Lost: {err}. Retrying...");
                            } else {
                                published_logs += 1;
                            }
                        }
                        Err(err) => eprintln!("JSON serialization error: {err}"),
                    }
                }
            }
            Err(PcapError::TimeoutExpired) => continue,
            Err(err) => {
                eprintln!("Capture loop error on {device_name}: {err}");
                break;
            }
        }
    }

    println!(
        "\nCapture stopped. Total packets captured: {total_packets}, structured logs emitted: {emitted_logs}, published to Redis: {published_logs}"
    );
    Ok(())
}

fn select_default_device() -> Result<Device, Box<dyn std::error::Error>> {
    if let Ok(Some(default_device)) = Device::lookup() {
        return Ok(default_device);
    }

    let devices = Device::list()?;
    let device = devices
        .into_iter()
        .find(|d| !d.name.contains("lo"))
        .ok_or_else(|| "No suitable non-loopback interface found".to_string())?;
    Ok(device)
}

fn open_capture(device: Device) -> Result<Capture<pcap::Active>, PcapError> {
    Capture::from_device(device)?
        .promisc(true)
        .snaplen(65_535)
        .timeout(1_000)
        .open()
}

fn packet_to_log(packet_data: &[u8], packet_len: u32) -> Option<PacketLog> {
    let sliced = SlicedPacket::from_ethernet(packet_data)
        .or_else(|_| SlicedPacket::from_ip(packet_data))
        .ok()?;

    let (src_ip, dst_ip) = match sliced.ip? {
        InternetSlice::Ipv4(header, _) => (
            header.source_addr().to_string(),
            header.destination_addr().to_string(),
        ),
        InternetSlice::Ipv6(header, _) => (
            header.source_addr().to_string(),
            header.destination_addr().to_string(),
        ),
    };

    let (protocol, src_port, dst_port) = match sliced.transport? {
        TransportSlice::Tcp(tcp) => ("TCP", tcp.source_port(), tcp.destination_port()),
        TransportSlice::Udp(udp) => ("UDP", udp.source_port(), udp.destination_port()),
        _ => return None,
    };

    Some(PacketLog {
        src_ip,
        dst_ip,
        protocol: protocol.to_string(),
        src_port,
        dst_port,
        risk_score: analyze_risk(dst_port),
        length: packet_len,
        timestamp: unix_ts().to_string(),
    })
}

fn analyze_risk(dst_port: u16) -> u8 {
    match dst_port {
        80 | 443 => 0,
        23 => 90,
        22 => 20,
        3389 => 70,
        _ => 40,
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn map_open_error(err: PcapError) -> Box<dyn std::error::Error> {
    let msg = err.to_string().to_lowercase();
    if msg.contains("permission") || msg.contains("denied") || msg.contains("operation not permitted") {
        return "Permission denied opening capture interface. Run with elevated privileges/capabilities."
            .into();
    }
    err.into()
}

fn start_firewall_listener(redis_url: String) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        let client = match redis::Client::open(redis_url.as_str()) {
            Ok(client) => client,
            Err(err) => {
                eprintln!("Firewall listener client init failed: {err}. Retrying...");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let mut connection = match client.get_connection() {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("Firewall listener connection failed: {err}. Retrying...");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let mut pubsub = connection.as_pubsub();
        if let Err(err) = pubsub.subscribe("firewall_commands") {
            eprintln!("Firewall listener subscribe failed: {err}. Retrying...");
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        eprintln!("Firewall command listener subscribed to firewall_commands.");

        loop {
            let message = match pubsub.get_message() {
                Ok(message) => message,
                Err(err) => {
                    eprintln!("Firewall listener stream error: {err}. Reconnecting...");
                    break;
                }
            };

            let payload: String = match message.get_payload() {
                Ok(payload) => payload,
                Err(err) => {
                    eprintln!("Firewall payload decode error: {err}");
                    continue;
                }
            };

            handle_firewall_command(&payload);
        }

        thread::sleep(Duration::from_secs(2));
    })
}

fn handle_firewall_command(payload: &str) {
    let command = match serde_json::from_str::<FirewallCommand>(payload) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("Firewall command parse error: {err}");
            return;
        }
    };

    let ip = match command.target_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!(
                "[AUDIT] REJECTED COMMAND: invalid IP '{}' (cmd_id={})",
                command.target_ip,
                command.command_id.as_deref().unwrap_or("unknown")
            );
            return;
        }
    };

    let exec_enabled = env::var("ENABLE_FIREWALL_EXECUTION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    match command.action {
        FirewallAction::BlockIp => {
            if exec_enabled {
                run_iptables(&["-A", "INPUT", "-s", &ip.to_string(), "-j", "DROP"]);
            }
            println!(
                "[AUDIT] BLOCKED IP: {} | site={} segment={} cmd_id={} reason={} requested_at={} exec={}",
                ip,
                command.site.as_deref().unwrap_or("unknown"),
                command.segment.as_deref().unwrap_or("unknown"),
                command.command_id.as_deref().unwrap_or("unknown"),
                command.reason.as_deref().unwrap_or("none"),
                command.requested_at.as_deref().unwrap_or("unknown"),
                exec_enabled
            );
        }
        FirewallAction::Quarantine => {
            if exec_enabled {
                run_iptables(&["-A", "INPUT", "-s", &ip.to_string(), "-j", "DROP"]);
                run_iptables(&["-A", "OUTPUT", "-d", &ip.to_string(), "-j", "DROP"]);
            }
            println!(
                "[AUDIT] QUARANTINED IP: {} | site={} segment={} cmd_id={} reason={} requested_at={} exec={}",
                ip,
                command.site.as_deref().unwrap_or("unknown"),
                command.segment.as_deref().unwrap_or("unknown"),
                command.command_id.as_deref().unwrap_or("unknown"),
                command.reason.as_deref().unwrap_or("none"),
                command.requested_at.as_deref().unwrap_or("unknown"),
                exec_enabled
            );
        }
        FirewallAction::Escalate => {
            println!(
                "[AUDIT] ESCALATED IP: {} | site={} segment={} cmd_id={} reason={} requested_at={}",
                ip,
                command.site.as_deref().unwrap_or("unknown"),
                command.segment.as_deref().unwrap_or("unknown"),
                command.command_id.as_deref().unwrap_or("unknown"),
                command.reason.as_deref().unwrap_or("none"),
                command.requested_at.as_deref().unwrap_or("unknown")
            );
        }
    }
}

fn run_iptables(args: &[&str]) {
    match Command::new("iptables").args(args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[AUDIT] iptables command failed: {stderr}");
        }
        Err(err) => {
            eprintln!("[AUDIT] unable to execute iptables: {err}");
        }
    }
}
