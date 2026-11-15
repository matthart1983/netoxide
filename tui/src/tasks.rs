//! The plain-language tasks of live mode: short forms that each end in one
//! request to the daemon. They are the same tasks the web interface offers.

use ox_schema::Config;
use serde_json::{Value, json};

/// What a form is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Task {
    Network,
    Forward,
    Vpn,
    Block,
    /// Ask what the box would do with a connection. Changes nothing.
    Check,
}

/// The Home menu, in the order the web interface lists the same things.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Choice {
    Review,
    Task(Task),
    Access,
}

pub const MENU: [(Choice, &str); 7] = [
    (Choice::Review, "Review and apply the waiting change"),
    (
        Choice::Task(Task::Network),
        "Add a network, such as one for guests",
    ),
    (
        Choice::Task(Task::Forward),
        "Let something in from the internet",
    ),
    (
        Choice::Task(Task::Vpn),
        "Give a phone or laptop remote access",
    ),
    (Choice::Task(Task::Block), "Block a device or a website"),
    (Choice::Access, "Change which networks can reach each other"),
    (
        Choice::Task(Task::Check),
        "Check whether something is blocked",
    ),
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    Text,
    /// One of a few answers, changed with the left and right arrows.
    Pick(Vec<String>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    /// Shown while the field is empty.
    pub hint: &'static str,
    pub kind: Kind,
    pub required: bool,
}

fn text(label: &'static str, hint: &'static str, required: bool) -> Field {
    Field {
        label,
        value: String::new(),
        hint,
        kind: Kind::Text,
        required,
    }
}

fn pick(label: &'static str, options: &[&str]) -> Field {
    Field {
        label,
        value: options.first().copied().unwrap_or("").to_string(),
        hint: "",
        kind: Kind::Pick(options.iter().map(|o| o.to_string()).collect()),
        required: false,
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Form {
    pub task: Task,
    pub title: &'static str,
    pub about: &'static str,
    /// Something to know before sending it.
    pub note: &'static str,
    pub fields: Vec<Field>,
    pub at: usize,
    /// Why the form was not sent.
    pub error: Option<String>,
}

/// What a connection uses, for the check: the label, the protocol, the port.
const USING: [(&str, &str, &str); 5] = [
    ("Secure web (HTTPS)", "tcp", "443"),
    ("Web (HTTP)", "tcp", "80"),
    ("DNS", "udp", "53"),
    ("SSH", "tcp", "22"),
    ("Ping", "icmp", ""),
];

/// True when the text is an address or a network, so a device and not a
/// website's name.
pub fn is_device(what: &str) -> bool {
    let what = what.trim();
    let addr = what.split('/').next().unwrap_or("");
    addr.parse::<std::net::IpAddr>().is_ok()
}

impl Form {
    pub fn new(task: Task, config: &Config) -> Form {
        let (title, about, note, fields) = match task {
            Task::Network => {
                // An inside port that is a real port: not the internet side, not a VLAN.
                let ports: Vec<&str> = config
                    .interfaces
                    .iter()
                    .filter(|(_, i)| !i.default_route && i.vlan.is_none())
                    .map(|(name, _)| name.as_str())
                    .collect();
                (
                    "Add a network",
                    "A network of its own for guests, cameras or anything you want kept apart. Devices on it get an address and DNS from the box. It reaches none of your other networks until you allow that under Access.",
                    "The network travels on that port as a VLAN. Set the switch or access point there to use the same VLAN number.",
                    vec![
                        text("What is it for?", "Guest Wi-Fi", true),
                        pick("On which port?", &ports),
                        text("VLAN number", "20", true),
                        text("The box's address on it", "chosen for you", false),
                        pick("Can it reach the internet?", &["Yes", "No"]),
                    ],
                )
            }
            Task::Forward => (
                "Let something in from the internet",
                "Lets people on the internet reach one port of one device inside. The rule it needs is added for you and checked.",
                "",
                vec![
                    text("What is it for?", "Home Assistant", true),
                    text("Outside port", "tcp/443", true),
                    text("Inside device address", "192.168.10.20", true),
                    text("Inside port, if different", "same", false),
                ],
            ),
            Task::Vpn => (
                "Give a phone or laptop remote access",
                "Lets a device reach the inside network from anywhere, over WireGuard. The first device also sets the VPN up.",
                "After this you get the settings for the device, once, with a code to scan if the window is big enough.",
                vec![
                    text("What is it?", "laptop", true),
                    text(
                        "How the device finds this box from outside",
                        "home.example.net",
                        true,
                    ),
                    text(
                        "The device's public key, if it made its own",
                        "make one for it",
                        false,
                    ),
                ],
            ),
            Task::Block => (
                "Block a device or a website",
                "Give the address of a device to drop everything it sends. Or give the name of a website to stop every device looking it up.",
                "A website block works through the box's DNS. A device that uses another DNS server, or a browser with its own secure DNS, is not affected.",
                vec![
                    text(
                        "Device address or website name",
                        "192.168.10.66 or example.com",
                        true,
                    ),
                    text("For a device: what is it?", "Smart TV", false),
                    pick("Do what?", &["Block it", "Unblock a website"]),
                ],
            ),
            Task::Check => (
                "Is something blocked?",
                "Say which device is trying to reach what, and the box says what it would do and why. Nothing is changed.",
                "",
                vec![
                    text("From (address of the device)", "192.168.10.50", true),
                    text("To (address)", "1.1.1.1", true),
                    pick("Using", &USING.iter().map(|u| u.0).collect::<Vec<_>>()),
                ],
            ),
        };
        Form {
            task,
            title,
            about,
            note,
            fields,
            at: 0,
            error: None,
        }
    }

    fn value(&self, i: usize) -> &str {
        self.fields[i].value.trim()
    }

    pub fn step(&mut self, down: bool) {
        let n = self.fields.len();
        self.at = if down {
            (self.at + 1) % n
        } else {
            (self.at + n - 1) % n
        };
    }

    /// Moves a pick field to its next or previous answer.
    pub fn turn(&mut self, forward: bool) {
        let field = &mut self.fields[self.at];
        if let Kind::Pick(options) = &field.kind
            && !options.is_empty()
        {
            let at = options.iter().position(|o| *o == field.value).unwrap_or(0);
            let n = options.len();
            field.value = options[if forward {
                (at + 1) % n
            } else {
                (at + n - 1) % n
            }]
            .clone();
        }
    }

    pub fn type_char(&mut self, c: char) {
        let field = &mut self.fields[self.at];
        match field.kind {
            Kind::Text if !c.is_control() && field.value.chars().count() < 120 => {
                field.value.push(c);
            }
            Kind::Pick(_) if c == ' ' => self.turn(true),
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        let field = &mut self.fields[self.at];
        if field.kind == Kind::Text {
            field.value.pop();
        }
    }

    /// The first required field left empty, as a sentence.
    fn missing(&self) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.required && f.value.trim().is_empty())
            .map(|f| format!("Fill in \"{}\" first.", f.label))
    }

    /// The request this form makes: the route and its body. Only for the
    /// tasks that change something.
    pub fn request(&self) -> Result<(&'static str, Value), String> {
        if let Some(missing) = self.missing() {
            return Err(missing);
        }
        let number = |i: usize, what: &str| -> Result<u64, String> {
            self.value(i)
                .parse::<u64>()
                .map_err(|_| format!("{what} must be a number, and '{}' is not.", self.value(i)))
        };
        match self.task {
            Task::Network => {
                if self.value(1).is_empty() {
                    return Err("This box has no inside port to put a network on.".into());
                }
                let mut body = json!({
                    "name": self.value(0),
                    "port": self.value(1),
                    "vlan": number(2, "The VLAN number")?,
                    "internet": self.value(4) == "Yes",
                });
                if !self.value(3).is_empty() {
                    body["address"] = json!(self.value(3));
                }
                Ok(("/v1/actions/network", body))
            }
            Task::Forward => {
                let mut body = json!({
                    "name": self.value(0),
                    "port": self.value(1),
                    "to": self.value(2),
                });
                if !self.value(3).is_empty() {
                    body["to_port"] = json!(number(3, "The inside port")?);
                }
                Ok(("/v1/actions/forward", body))
            }
            Task::Vpn => {
                let mut body = json!({ "name": self.value(0), "endpoint": self.value(1) });
                if !self.value(2).is_empty() {
                    body["public_key"] = json!(self.value(2));
                }
                Ok(("/v1/actions/vpn-peer", body))
            }
            Task::Block => {
                let what = self.value(0);
                let unblock = self.value(2) != "Block it";
                if is_device(what) {
                    if unblock {
                        return Err("Only a website can be unblocked here. To let a device back in, remove its block rule on the detailed screens or with ox.".into());
                    }
                    let mut body = json!({ "address": what });
                    if !self.value(1).is_empty() {
                        body["name"] = json!(self.value(1));
                    }
                    Ok(("/v1/actions/block", body))
                } else {
                    Ok((
                        "/v1/actions/block-site",
                        json!({ "name": what, "block": !unblock }),
                    ))
                }
            }
            Task::Check => Err("a check is not a change".into()),
        }
    }

    /// The connection a check asks about: source, destination, protocol, port.
    pub fn connection(&self) -> Result<(String, String, String, String), String> {
        if let Some(missing) = self.missing() {
            return Err(missing);
        }
        let (_, proto, port) = USING
            .iter()
            .find(|u| u.0 == self.value(2))
            .copied()
            .unwrap_or(USING[0]);
        Ok((
            self.value(0).to_string(),
            self.value(1).to_string(),
            proto.to_string(),
            port.to_string(),
        ))
    }
}

/// What the daemon said after a task: the waiting change it saved, what it
/// did in sentences, and for a VPN device the settings to hand over.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Saved {
    pub candidate: String,
    pub done: Vec<String>,
    pub device: Option<Device>,
}

/// A VPN device's settings. They may hold its private key, so they are
/// shown once and kept nowhere.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Device {
    pub config: String,
    /// True when the box made the device's key, so the settings are complete.
    pub key_made_here: bool,
}

pub fn parse_saved(v: &Value) -> Saved {
    let list = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(String::from))
            .collect()
    };
    Saved {
        candidate: v["candidate"].as_str().unwrap_or("").to_string(),
        done: list(&v["done"]),
        device: v["client_config"].as_str().map(|config| Device {
            config: config.to_string(),
            key_made_here: v["key_made_here"] == true,
        }),
    }
}
