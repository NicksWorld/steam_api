extern crate reqwest;
extern crate serde;
extern crate serde_json;

extern crate crc;
extern crate openssl;

extern crate prost;

extern crate hex;

pub mod steam_crypto;
pub mod steam_user;

pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/google.protobuf.rs"));
    pub mod steammessages {
	include!(concat!(env!("OUT_DIR"), "/steammessages.rs"));
    }
}

#[test]
fn test() {
    use steam_user::SteamUser;

    let user = SteamUser::new();
    user.login().unwrap();
}
