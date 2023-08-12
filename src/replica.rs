use {
	crate::{tobs58::ToBs58, Protocol},
	dusk_bls12_381_sign::{PublicKey, SecretKey},
	dusk_bytes::Serializable,
	futures::{SinkExt, StreamExt},
	nanoid::nanoid,
	rmp_serde::{from_slice, to_vec},
	sha3::{Digest, Sha3_256},
	std::net::SocketAddr,
	tokio::{io::AsyncWriteExt, net::TcpStream},
	tokio_util::codec::{Framed, LengthDelimitedCodec},
};

pub async fn start_replica(server: SocketAddr) -> anyhow::Result<()> {
	let connection = TcpStream::connect(server).await?;
	let mut protocol = Framed::new(connection, LengthDelimitedCodec::new());

	let replica_secret = SecretKey::random(&mut rand::thread_rng());
	let replica_public = PublicKey::from(&replica_secret);

	println!(
		"replica identity: {}",
		bs58::encode(replica_public.to_bytes()).into_string()
	);

	protocol
		.send(to_vec(&Protocol::HelloReplica(replica_public.to_bytes()))?.into())
		.await?;

	loop {
		let message = protocol.next().await.unwrap()?;
		let message = from_slice::<Protocol>(&message)?;

		let mut remaining = match message {
			Protocol::StoreFile(0) => panic!("Protocol violation"),
			Protocol::StoreFile(len) => len,
			_ => panic!("Protocol violation"),
		};

		let temp_name = nanoid!();
		let mut hasher = Sha3_256::new();
		let mut file = tokio::fs::File::create(temp_name.clone()).await?;

		while remaining != 0 {
			let chunk = protocol.next().await.unwrap()?;
			file.write_all(&chunk).await?;
			hasher.update(&chunk);
			remaining = remaining.saturating_sub(chunk.len() as u64);
		}

		let hash: [u8; 32] = hasher.finalize().as_slice().try_into()?;
		let signature = replica_secret.sign(&replica_public, &hash).to_bytes();

		// rename the file to its hash
		tokio::fs::rename(temp_name, hash.to_bs58()).await?;

		// send a confirmation back to the server
		protocol
			.send(to_vec(&Protocol::FileStored { hash, signature })?.into())
			.await?;
		println!("done");
	}
}
