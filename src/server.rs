use {
	crate::{tobs58::ToBs58, Protocol},
	bytes::Bytes,
	dashmap::DashMap,
	dusk_bls12_381_sign::{PublicKey, SecretKey, Signature, APK},
	dusk_bytes::Serializable,
	futures::{SinkExt, StreamExt},
	rmp_serde::{from_slice, to_vec},
	sha3::{Digest, Sha3_256},
	std::{net::SocketAddr, sync::Arc},
	tokio::{
		net::{TcpListener, TcpStream},
		sync::RwLock,
	},
	tokio_util::codec::{Framed, LengthDelimitedCodec},
};

type Stream = Framed<TcpStream, LengthDelimitedCodec>;

pub async fn start_server(port: u16) -> anyhow::Result<()> {
	let listen_addr = SocketAddr::from(([0, 0, 0, 0], port));
	let listener = TcpListener::bind(listen_addr).await?;

	let server_secret = SecretKey::random(&mut rand::thread_rng());
	let server_public = PublicKey::from(&server_secret);
	let aggregate_identity = Arc::new(RwLock::new(APK::from(&server_public)));
	let replicas = Arc::new(DashMap::<[u8; 96], Stream>::new());

	println!("server started on port: {port}");
	println!(
		"server identity: {}",
		aggregate_identity.read().await.to_bs58()
	);

	loop {
		let replicas = Arc::clone(&replicas);
		let aggregate_identity = Arc::clone(&aggregate_identity);
		let (socket, from) = listener.accept().await?;
		let mut protocol = Framed::new(socket, LengthDelimitedCodec::new());
		tokio::spawn(async move {
			let replicas = Arc::clone(&replicas);
			let message = protocol.next().await.unwrap()?;
			match from_slice::<Protocol>(&message)? {
				Protocol::HelloReplica(pubkey) => {
					replicas.insert(pubkey, protocol);
					let pubkey = PublicKey::from_bytes(&pubkey)
						.map_err(|_| anyhow::anyhow!("invalid pubkey bytes"))?;
					aggregate_identity.write().await.aggregate(&[pubkey]);

					println!(
						"replica {from} connected, new aggregate identity: {}",
						aggregate_identity.read().await.to_bs58()
					);
				}
				Protocol::HelloClient => {
					serve_client(
						&mut protocol,
						Arc::clone(&replicas),
						*aggregate_identity.read().await,
						server_secret,
					)
					.await?;
				}
				_ => anyhow::bail!("protocol violation"),
			}

			Ok::<_, anyhow::Error>(())
		});
	}
}

async fn serve_client(
	protocol: &mut Stream,
	replicas: Arc<DashMap<[u8; 96], Stream>>,
	aggregate_identity: APK,
	server_secret: SecretKey,
) -> anyhow::Result<()> {
	protocol
		.send(Bytes::from(to_vec(&Protocol::Ack(
			aggregate_identity.to_bytes(),
		))?))
		.await?;

	let store_command = protocol.next().await.unwrap()?;
	let store_command = from_slice::<Protocol>(&store_command)?;
	let mut remaining = match store_command {
		Protocol::StoreFile(0) => panic!("Protocol violation"),
		Protocol::StoreFile(len) => len,
		_ => panic!("Protocol violation"),
	};

	// prepare all replicas for receiving a file
	for mut replica in replicas.iter_mut() {
		replica
			.value_mut()
			.send(Bytes::from(to_vec(&Protocol::StoreFile(remaining))?))
			.await?;
	}

	let mut hasher = Sha3_256::new();

	// for each chunk received from the client
	// send it to all replicas
	while remaining != 0 {
		let chunk = protocol.next().await.unwrap()?;
		let chunk = chunk.freeze();
		hasher.update(&chunk);
		for mut replica in replicas.iter_mut() {
			replica.value_mut().send(chunk.clone()).await?;
		}
		remaining = remaining.saturating_sub(chunk.len() as u64);
	}

	// now all replicas will respond with their signatures
	// and their hash of the received bytes. Our hash and their
	// hash must match, to ensure that the file did not get corrupt
	// during transmission, and their signature serves as a certificate
	// of availability.

	// Aggregating all received certificates of avilaiblity gives us
	// a combined certificate that the file is available on all replicas.
	let self_hash: [u8; 32] = hasher.finalize().as_slice().try_into()?;
	let server_public = (&server_secret).into();

	// own signature
	let mut aggregate_signature = server_secret.sign(&server_public, &self_hash);

	for mut replica in replicas.iter_mut() {
		let seal_message = replica.value_mut().next().await.unwrap()?;
		let seal_message = from_slice::<Protocol>(&seal_message)?;
		let (hash, sig) = match seal_message {
			Protocol::FileStored { hash, signature } => (hash, signature),
			_ => panic!("Protocol violation"),
		};

		if hash != self_hash {
			panic!("file corrupt on {}", replica.key().to_bs58());
		}

		let sig = Signature::from_bytes(&sig)
			.map_err(|_| anyhow::anyhow!("invalid signature bytes"))?;
		aggregate_signature = aggregate_signature.aggregate(&[sig]);
	}

	protocol
		.send(
			to_vec(&Protocol::FileStored {
				hash: self_hash,
				signature: aggregate_signature.to_bytes(),
			})?
			.into(),
		)
		.await?;

	println!("file stored successfully!");
	println!(
		"certificate of availability: {}",
		aggregate_signature.to_bytes().to_bs58()
	);
	Ok(())
}
