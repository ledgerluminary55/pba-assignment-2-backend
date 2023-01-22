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

#[derive(Serialize)]
struct AccountState {
    exists: bool,
    account: String,
    balance: u128,
    nonce: u32,
}

#[post("/transfer/<from>/<to>/<amount>")]
fn transfer(from: u8, to: u8, amount: u128) -> Json<String> {
    let key_pair_1 = generate_key_pair(from);
    let key_pair_2 = generate_key_pair(to);
    let account_nonce = get_account_state(from).0.nonce;

    let call_0 = Call::Transfer(key_pair_1.public().0, key_pair_2.public().0, amount);
    println!("call_0: {:?}", call_0);
    let ext_0 = create_signed_extrinsic(call_0, &key_pair_1, account_nonce);
    submit_extrinsic(ext_0);

    Json("Transfered".to_string())
}

#[post("/mint/<account_id>/<amount>")]
fn mint(account_id: u8, amount: u128) -> Json<String> {
    let key_pair = generate_key_pair(account_id);
    let account_nonce = get_account_state(account_id).0.nonce;

    let call_0 = Call::Mint(key_pair.public().0, amount);
    println!("call_0: {:?}", call_0);
    let ext_0 = create_signed_extrinsic(call_0, &key_pair, account_nonce);
    submit_extrinsic(ext_0);

    Json("Minted".to_string())
}

#[get("/account_state/<account_id>")]
fn get_account_state(account_id: u8) -> Json<AccountState> {
    let key;
    if account_id < 3 {
        key = generate_key_pair(account_id).public().0;
    } else {
        let public_key_bytes =
            &hex_literal::hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        key = *public_key_bytes;
    }

    let method = "state_getStorage";
    let data = hex::encode(key);
    let res = send(method, &data);

    let acc = parse_result(&res);
    match acc {
        Some(acc) => Json(AccountState {
            exists: true,
            account: data,
            balance: acc.balance,
            nonce: acc.nonce,
        }),

        None => Json(AccountState {
            exists: false,
            account: data,
            balance: 0,
            nonce: 0,
        }),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/api", routes![get_account_state, mint, transfer])
        .attach(CORS)
}

fn generate_key_pair(value: u8) -> sr25519::Pair {
    let seed = [value; 32];
    sr25519::Pair::from_seed(&seed)
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

fn parse_result(res: &String) -> Option<Account> {
    // Remove the quotes and the 0x from the response
    let result = res.replace("\"", "").replace("%", "").replace("0x", "");

    // Decode the hex string into an Account struct
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
