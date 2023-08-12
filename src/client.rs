use {
	crate::{tobs58::ToBs58, Protocol},
	dusk_bls12_381_sign::APK,
	dusk_bytes::Serializable,
	futures::{SinkExt, StreamExt},
	rmp_serde::{from_slice, to_vec},
	sha3::{Digest, Sha3_256},
	std::{net::SocketAddr, path::PathBuf},
	tokio::{io::AsyncReadExt, net::TcpStream},
	tokio_util::codec::{Framed, LengthDelimitedCodec},
};

pub async fn start_client(
	server: SocketAddr,
	file: PathBuf,
) -> anyhow::Result<()> {
	let connection = TcpStream::connect(server).await?;
	let mut protocol = Framed::new(connection, LengthDelimitedCodec::new());
	protocol
		.send(to_vec(&Protocol::HelloClient)?.into())
		.await?;

	let message = protocol.next().await.unwrap()?;
	let message = from_slice::<Protocol>(&message)?;

	let server_identity = APK::from_bytes(&match message {
		Protocol::Ack(identity) => identity,
		_ => panic!("Protocol violation"),
	})
	.map_err(|_| anyhow::anyhow!("invalid server identity format"))?;

	println!("server identity: {}", server_identity.to_bs58());

	let mut file = tokio::fs::File::open(file).await?;
	let mut remaining = file.metadata().await?.len();

	protocol
		.send(to_vec(&Protocol::StoreFile(remaining))?.into())
		.await?;

	let mut buffer = vec![0; 1024];
	let mut hasher = Sha3_256::new();

	while remaining != 0 {
		let read = file.read(&mut buffer).await?;
		protocol.send(buffer[..read].to_vec().into()).await?;
		hasher.update(&buffer[..read]);
		remaining = remaining.saturating_sub(read as u64);
	}

	// wait for confirmation
	let message = protocol.next().await.unwrap()?;
	let message = from_slice::<Protocol>(&message)?;
	let expected_hash: [u8; 32] = hasher.finalize().try_into()?;
	let (hash, sig) = match message {
		Protocol::FileStored { hash, signature } => (hash, signature),
		_ => panic!("Protocol violation"),
	};

	if hash != expected_hash.as_slice() {
		panic!(
			"File storage failed, expected the server to store a file with hash {}, \
			 but it stored a file with hash {}",
			expected_hash.to_bs58(),
			hash.to_bs58()
		);
	}

	println!("file {} stored successfully.", hash.to_bs58());
	println!("certificate of availability: {}", sig.to_bs58());
	println!("availability set identity: {}", server_identity.to_bs58());

	let sig = dusk_bls12_381_sign::Signature::from_bytes(&sig)
		.map_err(|_| anyhow::anyhow!("invalid signature bytes"))?;
	server_identity.verify(&sig, &hash).unwrap();
	println!("certificate of availability is valid.");

	Ok(())
}
