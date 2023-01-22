use parity_scale_codec::{Decode, Encode};
use rocket::form::{Form, FromForm};
use rocket::serde::json::Json;
use rocket::{
    data::{self, FromData},
    post,
};
use serde::Serialize;
use serde_json::*;
use sp_core::*;
use sp_core::{hexdisplay::AsBytesRef, H512};
use tungstenite::{connect, Message};
use url::Url;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}
#[cfg_attr(
    feature = "std",
    derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf)
)]
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum Call {
    SetValue(u32),
    Transfer([u8; 32], [u8; 32], u128),
    Mint([u8; 32], u128),
    Upgrade(Vec<u8>),
    PrintState,
    SetFeeValue(u128),
}

#[cfg_attr(
    feature = "std",
    derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf)
)]
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct BasicSignedPayload {
    pub is_signed: bool,
    pub signature: H512,
    pub public_key: [u8; 32],
    pub nonce: u32,
}

#[cfg_attr(
    feature = "std",
    derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf)
)]
#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone)]
pub struct BasicExtrinsic(Call, BasicSignedPayload);

#[cfg_attr(
    feature = "std",
    derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf)
)]
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Default)]
pub struct Account {
    pub balance: u128,
    pub nonce: u32,
}

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

// #[get("/say_hi"/<name>")]
// fn say_hi(name: &str) -> Json<&'static str> {
//     Json("Hi, {}",name)
// }

#[derive(Serialize)]
struct AccountState {
    account: String,
    balance: u128,
    nonce: u32,
}

#[post("/mint/<account_id>/<amount>")]
fn mint(account_id: usize, amount: u128) -> Json<String> {
    let key_pairs = generate_key_pairs(2);
    let key = key_pairs[account_id].public().0;

    let call_0 = Call::Mint(key_pairs[0].public().0, 100);
    let ext_0 = create_signed_extrinsic(call_0, &key_pairs[0], 0);
    submit_extrinsic(ext_0);

    Json("Minted".to_string())
}

#[get("/account_state/<account_id>")]
fn get_account_state(account_id: usize) -> Json<AccountState> {
    let key_pairs = generate_key_pairs(2);
    let key = key_pairs[account_id].public().0;
    let method = "state_getStorage";
    let data = hex::encode(key);
    let res = send(method, &data);

    let acc = parse_result(&res);
    match acc {
        Some(acc) => Json(AccountState {
            account: data,
            balance: acc.balance,
            nonce: acc.nonce,
        }),

        None => Json(AccountState {
            account: data,
            balance: 0,
            nonce: 0,
        }),
    }
}

#[launch]
fn rocket() -> _ {
    let authority_key_pair = generate_authority_key_pair();
    let key_pairs_amount = 4;

    rocket::build()
        .mount("/", routes![index])
        .mount("/api", routes![get_account_state, mint])
        .attach(CORS)
}
// fn main() {
//     let authority_key_pair = generate_authority_key_pair();
//     let key_pairs_amount = 4;
//     let key_pairs = generate_key_pairs(key_pairs_amount);
//     //let mut nonces = vec![0; key_pairs_amount];

//     // let call_0 = Call::Mint(key_pairs[0].public().0, 100);
//     // let ext_0 = create_signed_extrinsic(call_0, &key_pairs[0], 0);
//     // submit_extrinsic(ext_0);

//     // let call_1 = Call::Transfer(key_pairs[0].public().0, key_pairs[1].public().0, 50);
//     // let ext_1 = create_signed_extrinsic(call_1, &key_pairs[0], 1);
//     // submit_extrinsic(ext_1);

//     // let call_2 = Call::PrintState;
//     // let ext_2 = create_signed_extrinsic(call_2, &key_pairs[0],0);
//     // submit_extrinsic(ext_2);

// read_account_state(key_pairs[0].public().0);
// read_account_state(key_pairs[1].public().0);
//     read_account_state(authority_key_pair.public().0);
// }

fn generate_authority_key_pair() -> sr25519::Pair {
    let seed = [1; 32];
    let pair = sr25519::Pair::from_seed(&seed);
    println!("Authority Keypair Public Key: {:?}", pair.public());
    pair
}

fn generate_key_pairs(amount: usize) -> Vec<sr25519::Pair> {
    let mut key_pairs = vec![];
    let mut seed = [0; 32];
    for i in 0..amount {
        let pair = sr25519::Pair::from_seed(&seed);
        key_pairs.push(pair);
        seed[i] = seed[i] + 1;
    }
    print_keypairs(&key_pairs);
    key_pairs
}

fn print_keypairs(key_pairs: &Vec<sr25519::Pair>) {
    for key_pair in key_pairs {
        println!("Keypair Public Key: {:?}", key_pair.public());
    }
}

fn create_signed_extrinsic(call: Call, key_pair: &sr25519::Pair, nonce: u32) -> BasicExtrinsic {
    let sig = key_pair.sign(call.encode().as_bytes_ref());

    BasicExtrinsic(
        call,
        BasicSignedPayload {
            is_signed: true,
            signature: H512::from(sig.0),
            public_key: key_pair.public().0,
            nonce,
        },
    )
}

fn submit_extrinsic(ext: BasicExtrinsic) {
    let method = "author_submitExtrinsic";
    let data = hex::encode(ext.encode());
    send(method, &data);
}

fn read_account_state(key: [u8; 32]) {
    let method = "state_getStorage";
    let data = hex::encode(key);
    let res = send(method, &data);

    let acc = parse_result(&res);
    match acc {
        Some(acc) => {
            println!(
                "Account {} => Balance: {} | Nonce: {}",
                data, acc.balance, acc.nonce
            )
        }
        None => println!("Account {} => Null", data),
    }
}

fn parse_result(res: &String) -> Option<Account> {
    println!("res: {}", res);
    // Remove the quotes and the 0x from the response
    let result = res.replace("\"", "").replace("%", "").replace("0x", "");

    // Decode the hex string into an Account struct
    println!("res: {}", res);
    let account_bytes = hex::decode(result);
    match account_bytes {
        Ok(acc) => {
            let account = Account::decode(&mut &acc[..]).unwrap();
            Some(account)
        }
        Err(_) => None,
    }
}
fn send(method: &str, data: &String) -> String {
    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [data]
    });

    // Connect to the WS server locally
    let (mut socket, _response) =
        connect(Url::parse("ws://localhost:9944").unwrap()).expect("Can't connect");
    // Send the message to the node
    socket
        .write_message(Message::Text(json.to_string()))
        .unwrap();

    // Loop forever, handling parsing each message
    loop {
        let msg = socket.read_message().expect("Error reading message");
        match msg {
            tungstenite::Message::Text(s) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&s).expect("Can't parse to JSON");
                println!("parsed: {:?}", parsed);
                return parsed["result"].to_string();
            }
            _ => {}
        };
    }
}
