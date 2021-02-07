use std::io::Read;
use chrono::Timelike;
use chrono::Datelike;
use ansi_term::Color::{Red, Green};
use anyhow::Result;
use gqg_lib::database::Database;
use gqg_lib;

#[macro_use]
extern crate anyhow;

static GREY: ansi_term::Color = ansi_term::Color::Fixed(240);

fn logo() {
    eprintln!("
   __ _  __ _  __ _
  / _` |/ _` |/ _` |
 | (_| | (_| | (_| |
  \\__, |\\__, |\\__, |
   __/ |   | | __/ |
  |___/    |_||___/ v{}
", env!("CARGO_PKG_VERSION"));
}

fn help() -> ! {
    logo();
    println!("Usage:");
    println!("    gqg list                               : List of identities and friends.");
    println!("    gqg newid <local-name>                 : Create a new local identity with random key.");
    println!("    gqg befriend <friend-name> <id-string> : Add a friend.");
    println!("    gqg unfriend <friend-name>             : Remove a friend.");
    println!("    gqg receive                            : Decrypt incoming message.");
    println!("    gqg send <friend-name>                 : Encrypt outgoing message to friend.");
    println!("    gqg sendfile <friend-name> <file-name> : Encrypt outgoing file to friend.");
    println!("    gqg active <local-name>                : Set local identity for outgoing messages.");
    println!("    gqg dirs                               : List of paths to configuration file and local storage.");
    println!("Flags:");
    println!("    --stdout                               : Output to stdout, instead of file.");
    println!("    --insecure                             : Ignore sender authentication.");
    println!("");
    std::process::exit(1);
}

fn main() {
    match execute_cmd() {
        Ok(()) => {
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("{}", Red.paint(format!("Error: {}", err)));
            std::process::exit(1);
        }
    }
}

fn execute_cmd() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let action = if args.len() > 1 { &args[1] } else { "receive" };
    let mut db = Database::load();
    match action.as_ref() {
        "list" => {
            cmd_list(&db)
        }
        "newid" => {
            cmd_newid(args, &mut db)
        }
        "befriend" => {
            cmd_befriend(args, &mut db)
        }
        "unfriend" => {
            cmd_unfriend(args, &mut db)
        }
        "recv" | "receive" => {
            cmd_receive(&db)
        }
        "send" => {
            cmd_send(args, &db)
        }
        "sendfile" => {
            cmd_sendfile(args, &db)
        }
        "dirs" => {
            cmd_dirs()
        }
        "active" => {
            cmd_active(args, &mut db)
        }
        _ => {
            help();
        }
    }
}

macro_rules! arg {
    ($args:expr, $i:expr) => {
        if ($i < $args.len()) { &$args[$i] } else { help() }
    }
}

fn cmd_list(db: &Database) -> Result<()> {
    logo();
    let active_id = db.get_active_identity();
    println!("Identities:");
    for id in db.get_identities() {
        let name;
        if id.name == active_id.name {
            name = Green.paint(format!("(*) {}", &id.name)).to_string()
        }
        else {
            name = id.name.to_string()
        };
        println!("    {} {}", name, GREY.paint(id.get_public_id()));
    }
    println!("");
    let friends = db.get_friends();
    if friends.len() > 0 {
        println!("Friends:");
        for id in friends {
            println!("    {} {}", id.name, id.get_public_id());
        }
    }
    Ok(())
}

fn cmd_newid(args: Vec<String>, db: &mut Database) -> Result<()> {
    let name = arg!(&args, 2);
    db.add_identity(name.clone())?;
    Ok(())
}

fn cmd_befriend(args: Vec<String>, db: &mut Database) -> Result<()> {
    let name = arg!(&args, 2);
    let key = arg!(&args, 3);
    db.add_friend(name.clone(), key.clone())?;
    Ok(())
}

fn cmd_unfriend(args: Vec<String>, db: &mut Database) -> Result<()> {
    let name = arg!(&args, 2);
    db.del_friend(name.clone())?;
    Ok(())
}

fn cmd_receive(db: &Database) -> Result<()> {
    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload).unwrap();
    for id in db.get_identities() {
        if let Ok(msg) = gqg_lib::decode(&id.get_private_key(), payload.clone()) {
            let mut name = "untrusted";
            match db.find_friend_by_key(&msg.sender) {
                None => {
                    eprintln!("{}", Red.paint("BEWARE. Unknown sender: This message is NOT sent by your friends."));
                }
                Some(friend) => {
                    eprintln!("{}", Green.paint(format!("VERIFIED: {}", friend.name)));
                    name = &friend.name;
                }
            };
            let data;
            let out_path;
            match msg.data {
                gqg_lib::DecodedData::Message { contents } => {
                    let mut path = Database::message_path_buf();
                    let now = chrono::Utc::now();
                    path.push(format!("{}_{}-{:02}-{:02}_{:02}:{:02}:{:02}_{}.txt",
                        name,
                        now.year(),
                        now.month(),
                        now.day(),
                        now.hour(),
                        now.minute(),
                        now.second(),
                        now.timestamp_subsec_millis()));
                    data = contents;
                    out_path = path;
                }
                gqg_lib::DecodedData::File { file_name, contents } => {
                    let mut path = Database::file_path_buf();
                    path.push(file_name);
                    data = contents;
                    out_path = path;
                }
            }
            let out_path = out_path.to_str().unwrap().to_string();
            if let Ok(_) = std::fs::metadata(&out_path) {
                return Err(anyhow!("File already exists. Aborting."));
            }
            std::fs::write(&out_path, data).unwrap();
            println!("{}", out_path);
            return Ok(());
        }
    }
    Err(anyhow!("Failed to decrypt."))
}

fn cmd_send(args: Vec<String>, db: &Database) -> Result<()> {
    let name = arg!(&args, 2);
    let mut contents = String::new();
    std::io::stdin().read_to_string(&mut contents).unwrap();
    match db.find_friend(name) {
        None => {
            return Err(anyhow!("Friend not found."));
        }
        Some(friend) => {
            let to = friend.get_public_key();
            let active_id = db.get_active_identity();
            let from = active_id.get_private_key();
            match gqg_lib::encode(
                &from,
                &to,
                gqg_lib::Type::Message, gqg_lib::EncodeFlags::None,
                &contents.as_bytes())
            {
                Err(err) => {
                    Err(anyhow!("GQG library: {:?}", err))
                }
                Ok(msg) => {
                    println!("{}", msg);
                    Ok(())
                }
            }
        }
    }
}

fn cmd_sendfile(args: Vec<String>, db: &Database) -> Result<()> {
    let name = arg!(&args, 2);
    let file_path = arg!(&args, 3);
    let file_name = &std::path::Path::new(file_path)
        .file_name()
        .ok_or(anyhow!("Invalid path."))?
        .to_str()
        .ok_or(anyhow!("Invalid path."))?
        .to_string();
    let contents = std::fs::read(file_path).map_err(|_| anyhow!("Unable to open file."))?;
    match db.find_friend(name) {
        None => {
            Err(anyhow!("Friend not found."))
        }
        Some(friend) => {
            let to = friend.get_public_key();
            let active_id = db.get_active_identity();
            let from = active_id.get_private_key();
            match gqg_lib::encode(
                &from,
                &to,
                gqg_lib::Type::File { file_name }, gqg_lib::EncodeFlags::None,
                &contents)
            {
                Err(err) => {
                    Err(anyhow!("GQG library: {:?}", err))
                }
                Ok(msg) => {
                    println!("{}", msg);
                    Ok(())
                }
            }
        }
    }
}

fn cmd_dirs() -> Result<()> {
    logo();
    println!("Config file:       {}", Database::config_path());
    println!("File directory:    {}", Database::file_path_buf().to_str().unwrap().to_string());
    println!("Message directory: {}", Database::message_path_buf().to_str().unwrap().to_string());
    println!("");
    Ok(())
}

fn cmd_active(args: Vec<String>, db: &mut Database) -> Result<()> {
    let name = arg!(&args, 2);
    db.set_active_identity(name)?;
    Ok(())
}