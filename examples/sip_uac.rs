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
use std::sync::Arc;
use std::time::{Duration, Instant};

use liveaisip::call::execution::manager::CallManager;
use liveaisip::call::model::context::CallContext;
use liveaisip::call::{
    CallAction, CallCommand, CallEvent, CallRuntime, CallRuntimeConfig, CallThreadPhase,
    UdpSignaling,
};
use liveaisip::runtime::admission::AdmissionLeaseGroup;
use liveaisip::sip::auth::DigestCredentials;
use liveaisip::sip::builder::request::RequestBuilder;
use liveaisip::sip::headers::call_id::CallId;
use liveaisip::sip::headers::contact::Contact;
use liveaisip::sip::headers::content_type::ContentType;
use liveaisip::sip::headers::cseq::CSeq;
use liveaisip::sip::headers::from::FromHeader;
use liveaisip::sip::headers::max_forwards::MaxForwards;
use liveaisip::sip::headers::to::ToHeader;
use liveaisip::sip::headers::via::Via;
use liveaisip::sip::identifier::generate_wire_token;
use liveaisip::sip::parser::{message, uri};
use liveaisip::sip::transport::udp::UdpConfig;
use liveaisip::sip::transport::udp_driver::UdpDriverConfig;
use liveaisip::sip::types::header::HeaderKind;
use liveaisip::sip::types::method::Method;
use liveaisip::sip::validation;

const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(45);

struct Config {
    destination: SocketAddr,
    bind: SocketAddr,
    advertise: Option<IpAddr>,
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
    let mut signaling = UdpSignaling::bind(
        config.bind,
        config.destination,
        UdpDriverConfig::default(),
        UdpConfig::default(),
    )?;
    let bound = signaling.local_addr();
    let advertised = match config.advertise {
        Some(ip) => SocketAddr::new(ip, bound.port()),
        None if !bound.ip().is_unspecified() => bound,
        None => {
            return Err(input_error(
                "UDP route selection returned a wildcard address",
            ));
        }
    };
    signaling = signaling.with_advertised_addr(advertised)?;
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        signaling = signaling.with_credentials(DigestCredentials::new(
            username.as_str(),
            password.as_str(),
        )?);
    }

    let request = build_invite(&config, advertised)?;
    signaling.install_initial_invite(request)?;
    let context = CallContext::new(Duration::ZERO, 256)?;
    let runtime = CallRuntime::new(
        context,
        AdmissionLeaseGroup::new(),
        CallRuntimeConfig::default(),
    )?
    .with_udp_signaling(signaling)?;
    let mut manager = CallManager::new(1)?;
    let token = manager.spawn(1, runtime)?;
    manager.submit(token, CallEvent::Command(CallCommand::Start))?;

    println!(
        "calling {} through {} from UDP {} (Via {})",
        config.to, config.destination, bound, advertised
    );
    let started = Instant::now();
    let mut established: Option<Instant> = None;
    let mut hangup_sent = false;
    loop {
        let handle = manager.handle(token)?;
        let status = handle.status();
        if status.phase.is_terminal() {
            break;
        }
        if established.is_none() && started.elapsed() >= config.setup_timeout {
            eprintln!("setup timeout; cancelling call");
            manager.submit(token, CallEvent::Command(CallCommand::Hangup))?;
            hangup_sent = true;
        }
        if let Some(at) = established
            && !hangup_sent
            && at.elapsed() >= config.duration
        {
            println!("call duration elapsed; sending BYE");
            manager.submit(token, CallEvent::Command(CallCommand::Hangup))?;
            hangup_sent = true;
        }

        match manager.receive_actions(token, Duration::from_millis(100)) {
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
            Err(_) if matches!(status.phase, CallThreadPhase::Completed) => break,
            Err(error) => return Err(Box::new(error)),
        }
    }

    let exit = manager.remove(token)?;
    println!(
        "call thread exited {:?}; SIP datagrams processed={}, deadlines={}",
        exit.kind(),
        exit.runtime().processed_messages,
        exit.runtime().processed_deadlines
    );
    Ok(())
}

fn build_invite(
    config: &Config,
    advertised: SocketAddr,
) -> Result<validation::request::ValidatedRequest, Box<dyn Error>> {
    let request_uri = uri::parse_str(&config.to)?;
    if !request_uri.is_sip() {
        return Err(input_error("--to must be a sip: or sips: URI"));
    }
    let tag = generate_wire_token()?;
    let call_token = generate_wire_token()?;
    let branch = generate_wire_token()?;
    let from = FromHeader::from_bytes(format!("<{}>;tag={tag}", config.from).as_bytes())?;
    let to = ToHeader::from_bytes(format!("<{}>", config.to).as_bytes())?;
    let call_id = CallId::new(format!("{call_token}@{}", advertised.ip()))?;
    let cseq = CSeq::new(1, Method::Invite)?;
    let via =
        Via::from_bytes(format!("SIP/2.0/UDP {advertised};branch=z9hG4bK-{branch}").as_bytes())?;
    let contact = Contact::from_bytes(format!("<sip:liveaisip@{advertised}>").as_bytes())?;
    let mut builder = RequestBuilder::new(
        Method::Invite,
        request_uri,
        &via,
        &from,
        &to,
        &call_id,
        &cseq,
        MaxForwards::new(70),
    )?;
    builder.push_typed(HeaderKind::Contact, &contact)?;
    let address_type = if advertised.is_ipv4() { "IP4" } else { "IP6" };
    let session_id = u64::from_str_radix(&call_token[..16], 16)?;
    let sdp = format!(
        "v=0\r\no=liveaisip {session_id} {session_id} IN {address_type} {}\r\n\
         s=LiveAISIP signaling-only call\r\nc=IN {address_type} {}\r\nt=0 0\r\n\
         m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n",
        advertised.ip(),
        advertised.ip()
    );
    let builder = builder.with_body(&ContentType::application_sdp(), sdp.as_bytes())?;
    let bytes = builder.build().serialize()?;
    let raw = message::parse(Arc::from(bytes.into_boxed_slice()))?;
    Ok(validation::request::validate(raw)?)
}

fn parse_args() -> Result<Config, Box<dyn Error>> {
    let mut destination = None;
    let mut bind = "0.0.0.0:0".parse::<SocketAddr>()?;
    let mut advertise = None;
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
        "Usage: cargo run --example sip_uac -- \\\n  --destination 127.0.0.1:5060 \\\n  --bind 0.0.0.0:0 --advertise 192.0.2.10 \\\n  --from sip:liveaisip@192.0.2.10 --to sip:1000@127.0.0.1 \\\n  [--username USER --password-env ENV] [--duration 5] \\\n  [--setup-timeout 45] [--verbose]"
    );
}
