# BGP Validation with RPKI

This project was a part of a submission to the cybersecurity course CY6740 Network Security. The goal of the project was to understand BGP UPDATEs (used to advertise and withdraw inter-AS routes), learn BGP advertisement validation using RPKI ROAs and identifying malicious BGP announcements. The assignment required students to validate each of the BGP UPDATE messages observed in the given files against the RPKI ROAs provided.

## Border Gateway Protocol (BGP) Security
The BGP is the standard inter-AS routing protocol. While it has mostly succeeded in allowing network operators to automatically route around network failures, its security model is fundamentally based on mutual trust between BGP peers. But, malicious ASes can advertise specially-crafted routes in an attempt to influence downstream route selection decisions, directing traffic that would not otherwise see these ASes. If malicious routes are accepted and traffic is redirected, malicious ASes can either inspect that traffic (metadata/traffic and/or content analysis) or simply drop the traffic, resulting in a large-scale denial-of-service attack.

In order to influence the route selection algorithm, malicious peers have two main inputs they can control: 
  1. Length of the AS path vector, and 
  2. Length of the advertised network prefix. 

## Resource Public Key Infrastructure (RPKI)
The RPKI is an effort to secure Internet routing. RPKI provides an out-of-band, cryptographically-secured mechanism for validating BGP announcements against signed statements that control how network prefixes can be advertised. Route origin authorizations (ROAs) allow an AS to state a verifiable constraint on both what AS is allowed to originate a path to an owned prefix, and how long a prefix from an address allocation can be advertised.

## Validating BGP Updates

As part of the assignment following files and folder's were provided:
  1. Snapshot of the RPKI obtained from the five RIRs that contain certificates and signed ROAs. 
  2. Set of BGP UPDATEs published by the Route Views Project. 
  
*Note: Each file in this data set is a bzip-compressed Multi-Threaded Routing Toolkit (MRT) stream.*

The set of possible decisions are valid, invalid, unknown, and unsafe.
  - Valid announcements are authorized by a verified ROA.
  - Invalid announcements are contradicted by a verified ROA.
  - Unknown announcements are not covered by a verified ROA.

## Output
Each detection is reported as a one-line JSON object with the following format:
```json
{
    "type": "invalid",              // Or, "unknown"
    "tv_sec": 0,                    // Timestamp in seconds since UNIX epoch
    "tv_usec": 0,                   // Timestamp microseconds
    "peer_ip": "10.0.0.1",          // Peer IP address
    "peer_asn": 0,                  // Peer ASN
    "prefix": "10.10.10.0/24",      // Prefix
    "as_path": [                    // AS path as a vector of sequences and sets
        {
            "type": "sequence",
            "asns": [1, 2, 3, 4]
        },
        {
            "type": "set",
            "asns": [5, 6, 7, 8]
        }
    ]
}
```
At the end a statistics object is printed on one line and taking the following form:
```json
{
    "total_messages": 0,    // Total number of MRT messages processed
    "total_invalid": 0,     // Total number of invalid prefix announcements
    "total_unknown": 0,     // Total number of unknown prefix announcements
}
```

## Build and Run

To build and run this project, you need [docker installed](https://docs.docker.com/engine/install/) on your machine.

Once docker is installed, clone the repository, and follow these steps:

1. Build the docker image - `docker build --pull --rm -f "rpki/Dockerfile" -t <image_name>:latest "rpki"`
2. Run the docker image - `docker run -it --rm -p -v <host_path>/data:/data:ro <image_name> /data/rpki-cache /data/mrt`

## References
1. [RFC 6480 - An Infrastructure to Support Secure Internet Routing](https://datatracker.ietf.org/doc/html/rfc6480)
2. [RFC 6488 - Signed Object Template for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc6488)
3. [RFC 6482 - A Profile for Route Origin Authorizations (ROAs)](https://datatracker.ietf.org/doc/html/rfc6482)
4. [RFC 6483 - Validation of Route Origination Using the Resource Certificate Public Key Infrastructure (PKI) and Route Origin Authorizations (ROAs)](https://datatracker.ietf.org/doc/html/rfc6483)
