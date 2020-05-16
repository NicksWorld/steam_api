extern crate prost_build;

fn main() {
    let mut entries = vec![];
    for entry in std::fs::read_dir("Protobufs/steam").unwrap() {
	let path = entry.unwrap().path();

	if path.extension().is_some() && path.extension().unwrap() == "proto" {
	    entries.push(path.to_str().unwrap().to_string());
	}
    }

    prost_build::compile_protos(&["Protobufs/steam/steammessages_clientserver_login.proto"], &["Protobufs", "Protobufs/steam"]).unwrap();
}
