# Certified replicas

This project demonstrates the use of BLS signature aggregation by having a file replicated on several nodes, where each node signs the hash of the received bytes and sends back to the server its signature, the server then aggregates those signatures and sends back the client an aggregate certificate of availability.

No edge cases are handled here and the system will break easily in cases like:
- Any of the replicas dies
- New replicas that join the system will invalidate all previously generated certificates and will change the cluster identity.
- Protocol violations
- malicious behaviour (such as declaring the wrong file length by the client)
- etc

The idea is that there is a group of machines that agree to store some value and the client gets a verifiable way of telling whether those nodes have stored the value, or at least pretended, because in theory they can just calculate the hash of incoming bytes and sign that without actually storing the data, but verifying that is a much larger project that involves implementing something like Proof of Space Time in Filecoin.

## Running

### 1. start the server:

```
cargo run server 9090
```

### 2. Start one or many replicas:

```
cargo run replica 127.0.0.1:9090
```

This can be run many times


### 3. Run the client with some sample file

eg. we will use the `Cargo.toml` or `Cargo.lock` file from this directory for convenience:

```
cargo run client 127.0.0.1:9090 Cargo.lock
```


after running the client command you should see an output like this:

```
server identity: xkPvXTNXriieAdaQLY6TkSW8HsN7YiZAhamjKNScY3wz9mqc5cyvb61e1fPSx4kEG37R44uYH3KLFbqBneuUbfnTCtMx8hC5kALAFZF2TcsLa85DSCHWo3buozfvpZoJgeg
file D7HvbbWUScXgP6hPHn9a4gxZydmd8eKziFpndsytzfzD stored successfully.
certificate of availability: 7Htnp7gcPyaVRvcSsKq8NeCUhVXQn1WuXqLs1noxNNmriNDSxA1JTQhxt5M7fBa11J
availability set identity: xkPvXTNXriieAdaQLY6TkSW8HsN7YiZAhamjKNScY3wz9mqc5cyvb61e1fPSx4kEG37R44uYH3KLFbqBneuUbfnTCtMx8hC5kALAFZF2TcsLa85DSCHWo3buozfvpZoJgeg
certificate of availability is valid.
```