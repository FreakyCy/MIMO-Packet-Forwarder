# MIMO-Packet-Forwarder

![CircleCI](https://circleci.com/gh/brocaar/chirpstack-packet-multiplexer.svg?style=svg)

The MIMO-Packet-Forwarder is under Development and not working
The MIMO-Packet-Forwarder utility forwards the [Semtech packet-forwarder](https://github.com/lora-net/packet_forwarder)
UDP data to one or more endpoints. It makes it possible to connect a
LoRa MIMO gateway to multiple networks. It is part of [ChirpStack](https://www.chirpstack.io).

## Install

## Building from source

### Binary

It is recommended to run the commands below inside a [Docker Compose](https://docs.docker.com/compose/)
environment.

```bash
docker-compose run --rm MIMO-Packet-Forwarder bash
```

```bash
# build binary
make

# create snapshot release
make snapshot

# run tests
make test
```

### Docker image

```bash
docker build -t IMAGENAME .
```

## Usage

Run `MIMO-Packet-Forwarder --help` for usage information.

## Example configuration

Executing `MIMO-Packet-Forwarder configfile` returns the following configuration
template:

```toml
[general]
# Log level
#
# debug=5, info=4, warning=3, error=2, fatal=1, panic=0
log_level=4


[MIMO-Packet-Forwarder]
# Bind
#
# The interface:port on which the packet-multiplexer will bind for receiving
# data from the packet-forwarder (UDP data).
bind="0.0.0.0:1700"


# Backends
#
# The backends to which the packet-multiplexer will forward the
# packet-forwarder UDP data.
#
# Example:
# [[MIMO-Packet-Forwarder.backend]]
# # Host
# #
# # The host:IP of the backend.
# host="192.16.1.5:1700"
#
# # Uplink only
#
# # This backend is for uplink only. It is not able to send data
# # back to the gateways.
# uplink_only=false
#
# # Gateway IDs
# #
# # The Gateway IDs to forward data for.
# gateway_ids = [
#   "0101010101010101",
#   "0202020202020202",
# ]
```

## Example docker compose setup

If you built the docker image for the packet multiplexer as above and wish to
run it through docker compose create a suitable location for volumes and
configfile to reside.

```
mkdir MIMO-Packet-Forwarder/config
touch MIMO-Packet-Forwarder/config/MIMO-Packet-Forwarder.toml
```

Save your template in the following just created location below. Edit as required
for multiplexer and backends.
`MIMO-Packet-Forwarder/config/MIMO-Packet-Forwarder.toml`

Example docker-compose

```
version: "3"
services:
  MIMO-Packet-Forwarder:
    image: MIMO-Packet-Forwarder:latest
    ports:
      - 1700:1700/udp
    volumes:
      - ./:/MIMO-Packet-Forwarder
      - ./config/MIMO-Packet-Forwarder.toml:/etc/MIMO-Packet-Forwarder/MIMO-Packet-Forwarder.toml:ro
```

To run...
`docker-compose up`

## Changelog

### v3.1.0

This release renames LoRa Packet Multiplexer to ChirpStack Packet Multiplexer.
See the [Rename Announcement](https://www.chirpstack.io/r/rename-announcement) for more information.

### v3.0.2

* Fix setting of configuration variable (used to resolve if backend allows downlink).

### v3.0.1

* Auto-lowercase configured gateway IDs.

### v3.0.0

* Initial release (part of LoRa Server v3 repository).