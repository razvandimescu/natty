# Use the natty CLI

To see the path of the connection, set `NATTY_LOG=debug`. The log shows `direct path to <key>` when the connection moves to a direct path. On the relay path, the relay caps the speed of each session. The default cap is 1 MiB/s.

`natty connect` first dials the agent. It then checks the grant. If one of these steps fails, the command stops with an error. When the connection to the agent closes later, `natty connect` dials again for the next TCP connection.

For a second service at the same time, start a second `natty connect` with its own key file. Add that key to the grants file. To see the services that the agent grants to your key, run `natty list '<key>@relay.numa.rs'`. `natty help` prints the commands and the environment variables.

The agent reads the grants file again every 5 s. When you remove a grant, the agent ends the open streams of that grant. When you remove the line of a key, the agent also closes the connections of that key. A key with no grant gets the same refusal for every service name. It cannot learn which services exist. The client sends a service name, never an address.

The image `ghcr.io/razvandimescu/natty:v0.0.4` holds the CLI for linux/amd64. It runs as user 65532. In CI, the image runs `natty key` with a read-only root file system and no capabilities. Keep the key file on a volume. A new key file gives the agent a new address.

To run the agent in Docker on a Linux host:

```sh
mkdir -p ~/.natty
docker run -d --name natty --network host --user "$(id -u):$(id -g)" \
  -v ~/.natty:/keys -e NATTY_KEY=/keys/key -v "$PWD:/config:ro" \
  ghcr.io/razvandimescu/natty:v0.0.4 \
  serve relay.numa.rs --grants /config/grants --service web=127.0.0.1:8000
docker logs natty
```

- `docker logs natty` shows `serving as <key>@relay.numa.rs`.
- `--user` lets the agent write its key file in `~/.natty`.
- `--network host` lets the agent reach the services of the host. The punch then goes through the NAT of the host only.
- Mount the folder of the grants file, not the file. An editor can replace the file and the container does not see a replaced file.
- `natty connect` does not work behind `-p`. It listens on 127.0.0.1 inside the container. Use the binary for it.

[docs/design.md](design.md#tunnel) specifies the protocol of the agent.
