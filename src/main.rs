use {
	clap::Parser,
	client::start_client,
	replica::start_replica,
	serde::{Deserialize, Serialize},
	serde_with::serde_as,
	server::start_server,
	std::{net::SocketAddr, path::PathBuf},
};

mod client;
mod replica;
mod server;
mod tobs58;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub enum Protocol {
	/// This is a message that is sent from a replica node to the server
	/// when it first connects. The argument to this handshake is the public
	/// key of the replica node.
	HelloReplica(#[serde_as(as = "[_; 96]")] [u8; 96]),

	/// This is the message that is sent from a client to the server when it
	/// first connects.
	HelloClient,

	/// This is the response sent from the server to either of the above nodes
	/// to acknowledge the connection. The returned value is the aggregate public
	/// key of all the replicas and the server.
	Ack(#[serde_as(as = "[_; 96]")] [u8; 96]),

	/// This is a message that is sent either from a client to the server
	/// or from the server to a replica that tells the recipient to store
	/// the next N bytes of the stream as a file.
	StoreFile(u64),

	/// This is a message that is sent from a replica to the server confirming
	/// that it has stored the file, the signature is the signature of the
	/// replica node and acts as a certificate of availability.
	///
	/// This is also the message sent back to the client to confirm that the
	/// file has been stored.
	FileStored { 
		hash: [u8; 32], 
		
		#[serde_as(as = "[_; 48]")] 
		signature: [u8; 48] 
	},
}

/// Select the mode of operation of this instance.
#[derive(Debug, Parser)]
#[command()]
enum OperatingMode {
	/// When running as s server, this instance will listen for incoming
	/// requests from clients. Clients send files to the server for storage.
	Server { port: u16 },

	/// Replicas are nodes responsible for storing copies of files submitted by
	/// the server.
	Replica { server: SocketAddr },

	/// Clients talk to the server to store files.
	Client { server: SocketAddr, file: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	match OperatingMode::parse() {
		OperatingMode::Server { port } => start_server(port).await,
		OperatingMode::Replica { server } => start_replica(server).await,
		OperatingMode::Client { server, file } => start_client(server, file).await,
	}
}
