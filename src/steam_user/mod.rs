use reqwest::blocking::get;
use reqwest::Url;

use serde::{Deserialize, Serialize};
mod cm_socket;
use cm_socket::CMSocket;

const PROTOCOL_ENDPOINT: &str = "https://api.steampowered.com/";
const PROTOCOL_VERSION: &str = "0001";

/// SteamApiResponse is used to remove the basic structure of a WebAPI response.
/// The desired response is expected to be in the response field.
#[derive(Debug, Serialize, Deserialize)]
pub struct SteamApiResponse<T> {
    /// The data being replied with
    response: T,
}

/// ConnectionManagerList stores the structure of the CMList.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionManagerList {
    /// Error message (if applicable)
    message: String,
    /// Error code
    result: i32,
    /// List of TCP servers
    serverlist: Vec<String>,
    /// Websockets for use on steam web
    serverlist_websockets: Vec<String>,
}

/// SteamUser stores all information required to connect to a steam account.
pub struct SteamUser;

impl SteamUser {
    /// Builds an API url for steam web.
    fn build_url(path: &str, query: &[(&str, &str)]) -> Result<Url, Box<dyn std::error::Error>> {
        let url = Url::parse_with_params(
            &format!("{}{}/v{}", PROTOCOL_ENDPOINT, path, PROTOCOL_VERSION),
            query,
        )?;

        Ok(url)
    }

    /// Fetches the CMList of sockets used for connecting
    fn get_cmlist() -> Result<ConnectionManagerList, Box<dyn std::error::Error>> {
        const FORMAT: &str = "json";
        const CELLID: i32 = 0;

        let request_url = SteamUser::build_url(
            "ISteamDirectory/GetCMList",
            &[("cellid", &CELLID.to_string()), ("format", FORMAT)],
        )?;

        let cm_list: SteamApiResponse<ConnectionManagerList> = get(request_url)?.json()?;
        Ok(cm_list.response)
    }

    pub fn login(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Decide on a CM Host for the connection, pinging servers is likely smarter.
        let cm_list = SteamUser::get_cmlist()?;
        let cm_host = &cm_list.serverlist[1];
        println!("Host: {}", cm_host);

        let mut listener = CMSocket::new(cm_host)?;
        listener.start_listener()?;

        Ok(())
    }

    pub fn new() -> SteamUser {
        SteamUser {}
    }
}
