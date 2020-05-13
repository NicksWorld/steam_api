extern crate reqwest;
extern crate serde;
extern crate serde_json;

extern crate crc;
extern crate openssl;

pub mod steam_crypto;
pub mod steam_user;

#[test]
fn test() {
    use steam_user::SteamUser;

    let user = SteamUser::new();
    user.login().unwrap();
}
