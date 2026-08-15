// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Real signaling-only UDP UAC for FreeSWITCH interoperability.

use std::env;
use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use liveaisip::call::CallAction;
use liveaisip::call::execution::thread::CallThreadConfig;
use liveaisip::runtime::{OutboundDialConfig, RuntimeEngine, RuntimeEngineConfig};
use liveaisip::sip::auth::DigestCredentials;
use liveaisip::sip::headers::retry_after::RetryAfter;
use liveaisip::sip::parser::uri;

const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(45);

struct Config {
    destination: SocketAddr,
    bind: SocketAddr,
    advertise: Option<IpAddr>,
    advertise_address: Option<SocketAddr>,
    from: String,
    to: String,
    username: Option<String>,
    password: Option<String>,
    duration: Duration,
    setup_timeout: Duration,
    verbose: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("LiveAISIP UAC failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_args()?;
    let caller = uri::parse_str(&config.from)?;
    let target = uri::parse_str(&config.to)?;
    let mut dial = OutboundDialConfig::new(caller, target, config.bind, config.destination)?
        .with_inactive_pcmu_sdp();
    dial = match (config.advertise_address, config.advertise) {
        (Some(address), None) => dial.with_advertised_addr(address)?,
        (None, Some(ip)) => dial.with_advertised_ip(ip)?,
        (Some(_), Some(_)) => {
            return Err(input_error(
                "--advertise and --advertise-address are mutually exclusive",
            ));
        }
        (None, None) => dial,
    };
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        dial = dial.with_credentials(DigestCredentials::new(
            username.as_str(),
            password.as_str(),
        )?);
    }
    let mut engine = RuntimeEngine::new(RuntimeEngineConfig::new(
        1,
        RetryAfter::new(3),
        CallThreadConfig::default(),
        Duration::from_secs(5),
    ))?;
    let dialed = engine.dial(1, dial, Duration::ZERO)?;
    let token = dialed.token();
    let bound = dialed.local_addr();
    let advertised = dialed.advertised_addr();

    println!(
        "calling {} through {} from UDP {} (Via/Contact {})",
        config.to, config.destination, bound, advertised
    );
    let started = Instant::now();
    let mut established: Option<Instant> = None;
    let mut hangup_sent = false;
    loop {
        let handle = engine.handle(token)?;
        let status = handle.status();
        if status.phase.is_terminal() {
            break;
        }
        if established.is_none() && started.elapsed() >= config.setup_timeout {
            eprintln!("setup timeout; cancelling call");
            engine.hangup(token)?;
            hangup_sent = true;
        }
        if let Some(at) = established
            && !hangup_sent
            && at.elapsed() >= config.duration
        {
            println!("call duration elapsed; sending BYE");
            engine.hangup(token)?;
            hangup_sent = true;
        }

        match engine.receive_actions(token, Duration::from_millis(100)) {
            Ok(Some(actions)) => {
                for action in actions {
                    if config.verbose {
                        println!("call action: {action:?}");
                    }
                    if matches!(action, CallAction::SelectBranch { .. }) && established.is_none() {
                        println!("dialog confirmed; ACK sent");
                        established = Some(Instant::now());
                    }
                    if let CallAction::Ended(reason) = action {
                        println!("call ended: {reason:?}");
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                let latest = engine.handle(token)?.status();
                if latest.phase.is_terminal() {
                    break;
                }
                return Err(Box::new(error));
            }
        }
    }

    let exit = engine.remove(token)?;
    let diagnostics = exit.runtime();
    println!(
        "call thread exited {:?}; final SIP status={:?}, messages={}, deadlines={}, reflexive_endpoint_observed={}, advertised_endpoint_mismatch={}",
        exit.kind(),
        diagnostics.last_sip_status,
        diagnostics.processed_messages,
        diagnostics.processed_deadlines,
        diagnostics.signaling_reflexive_endpoint_observed,
        diagnostics.signaling_advertised_endpoint_mismatch,
    );
    Ok(())
}

fn parse_args() -> Result<Config, Box<dyn Error>> {
    let mut destination = None;
    let mut bind = "0.0.0.0:0".parse::<SocketAddr>()?;
    let mut advertise = None;
    let mut advertise_address = None;
    let mut from = None;
    let mut to = None;
    let mut username = None;
    let mut password = None;
    let mut duration = Duration::from_secs(5);
    let mut setup_timeout = DEFAULT_SETUP_TIMEOUT;
    let mut verbose = false;
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--help" || argument == "-h" {
            print_usage();
            std::process::exit(0);
        }
        if argument == "--verbose" {
            verbose = true;
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| input_error(&format!("missing value after {argument}")))?;
        match argument.as_str() {
            "--destination" => destination = Some(value.parse()?),
            "--bind" => bind = value.parse()?,
            "--advertise" => advertise = Some(value.parse()?),
            "--advertise-address" => advertise_address = Some(value.parse()?),
            "--from" => from = Some(value.clone()),
            "--to" => to = Some(value.clone()),
            "--username" => username = Some(value.clone()),
            "--password" => password = Some(value.clone()),
            "--password-env" => password = Some(env::var(value)?),
            "--duration" => duration = Duration::from_secs(value.parse()?),
            "--setup-timeout" => setup_timeout = Duration::from_secs(value.parse()?),
            _ => return Err(input_error(&format!("unknown argument: {argument}"))),
        }
        index += 2;
    }
    if username.is_some() != password.is_some() {
        return Err(input_error(
            "--username requires --password or --password-env, and vice versa",
        ));
    }
    Ok(Config {
        destination: destination.ok_or_else(|| input_error("--destination is required"))?,
        bind,
        advertise,
        advertise_address,
        from: from.ok_or_else(|| input_error("--from is required"))?,
        to: to.ok_or_else(|| input_error("--to is required"))?,
        username,
        password,
        duration,
        setup_timeout,
        verbose,
    })
}

fn input_error(message: &str) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn print_usage() {
    println!(
        "Usage: cargo run --example sip_uac -- \\\n  --destination 127.0.0.1:5060 \\\n  --bind 0.0.0.0:0 [--advertise 192.0.2.10 | --advertise-address 192.0.2.10:5060] \\\n  --from sip:liveaisip@192.0.2.10 --to sip:1000@127.0.0.1 \\\n  [--username USER --password-env ENV] [--duration 5] \\\n  [--setup-timeout 45] [--verbose]"
    );
}
