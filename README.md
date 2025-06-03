# ECH Module Scanner

```
The ECH module can be used to scan domains/IPs and detect EncryptedClientHello Endpoints.
More specifically, this module tries to identify whether a given domain/IP hosts some service that is capable of establishing an EncryptedClientHello extension as speficied in [Draft-ietf-tls-esni-24](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
```

## Scanner workflow

The scanner imiates an ECH enabled client by supplying a correct/valid ECH configuration during the TLS handshake in the ClientHello message. Based on the specified options the scanner opens a network connection (TCP/UDP-Quic)to the target and tries to establish a TLS connection (waits at least until the handshake is finished, or the handshake gets aborted). 

Should the server accept the EncryptedClientHello, the target is marked as _enabled_ and meta-data about the connection is written, such as the __ClientHelloOuter__, the __ClientHelloInner__, and the __ServerHello__. In addition the used __ECH Config__, the targets IP address are logged in the same record.

Should the server indicate ECH rejection but provides __RetryConfigs__ through the _EncryptedExtions_ (part of the TLS specification), the scanner will parse these retry configs and perform a second attempt with the first retry config. Logging of data is the same as before with the addition of logging all retry configs returned by the server.

In the case of any TLS abortion or any other network related errors, the target is marked as _failed_ and no record is logged.

## Measuring TLS handshake latency

In addition to detecting enabled ECH deployments, the scanner can be instructed to measure the time the TLS handshake took. When enabled, an additional network connection of the same protocol is made before the ECH connection. This prior connection has neither a valid nor a _GREASE ECH_ configuration supplied and is used to anchor for comparison. 

Observation of latency measurements have shown that the initial connection might be biased by network related effects such as caching or else. This can result in an increased latency for the inital connection. Observation shows, that this bias is independed of what the initial connection is, and for both ECH connection or non-ECH connection this bias has been observed. To mitigate the bias the scanner accepts a `--conn-primer` flag which specifies a network connection to the target. The primer can be a _tcp_ connection, a _tls_ connection, or a _dns_ query. No information from the primer function is logged but each successful record will indicate which primer was used (none is the default).


## Usage

### Input Format
`zgrab2` expects a list of domains as input, with a single domain per row. Should the ECH configuration be known before the scan it can be provided as optional field behind the domain (ECH config __must__ be encoded as _base64_). If not provided the scanner will default to query the domain's HTTPS resource record and parse the ECH config from there, unless `--greased` is specified.

### Running the scanner
A simple scan can look like this:
```bash
$ echo "netd-research-one.de" | ./zgrab2 ech | zstd > scan.zst
```

This will scan the provided domain for ECH for the protocols http1, http2 and quic. A more specific measurement might look like this:

```bash
$ echo "netd-research-one.de" | ./zgrab2 ech \
    --measure-latency \ # instruct to measure target without ECH
    --protos h2 \ # only scan using http2
    --conn-primer dns # before each scan of a target do a DNS query to the target
```

__Note:__ The _echo_ input can be replaced by a `cat many_domains.txt | ...`


## Results

The following shows the result for the above command with latency measurements enabled.
the `data.ech.result` is arranged as list and includes as many connection details as specified protocols. In this case only _h2_ has been specified, thus result has length 1.
Within a connection detail, the _ClientHelloOuter/Inner_ and the _ServerHello_ can be found as well as metadata about the ECH configuration used for the connection (prefixed with `ech_`).
```json
{
  "domain": "netd-research-one.de",
  "data": {
    "ech": {
      "status": "success",
      "protocol": "ech",
      "result": [
        {
          "protocol": "h2",
          "error": null,
          "ech_version": 65037,
          "ech_config_id": 124,
          "ech_public_name": "cloudflare-ech.com",
          "kem_name": 32,
          "len_preference_list": 1,
          "ech_cipher_suites": [
            "{(cipher) kdf: SHA256, aead: AES128GCM}"
          ],
          "max_name_len": 0,
          "raw_extensions": "",
          "alpn_list": [
            "h3",
            "h2"
          ],
          "ipv4_hints": [
            "104.21.19.97",
            "172.67.185.187"
          ],
          "ipv6_hints": [
            "2606:4700:3034::6815:1361",
            "2606:4700:3034::ac43:b9bb"
          ],
          "ip": "172.67.185.187",
          "transport": "tcp",
          "tls_version": "TLS 1.3",
          "tls_handshake_duration_with_ech": 34,
          "tls_handshake_duration_without_ech": -1,
          "tls_handshake_anchor_ip": null,
          "ech_accepted": true,
          "tls_handshake_completed": true,
          "negotiated_protocol": "h2",
          "negotiated_cipher": "TLS_CHACHA20_POLY1305_SHA256",
          "retry_configs": null,
          "client_hello_outer": {
            "original": null,
            "vers": 771,
            "random": "5sgu5N2l3JfE8D3GJ6bVHjLIPeeXZuxozdzG14cZFZ4=",
            "session_id": "o3T3E0QG8qNdHa1r9yGaHmqkwvZcPntx0uaSt1bwv50=",
            "cipher_suites": [
              4867,
              4865,
              4866
            ],
            "compression_methods": "AA==",
            "server_name": "cloudflare-ech.com",
            "ocsp_stampling": true,
            "supported_curves": [
              25497,
              29,
              23,
              24,
              25
            ],
            "supported_points": null,
            "ticket_supported": false,
            "session_ticket": null,
            "supported_signature_algorithms": [
              2052,
              1027,
              2055,
              2053,
              2054,
              1025,
              1281,
              1537,
              1283,
              1539,
              513,
              515
            ],
            "supported_signature_algorithms_cert": null,
            "secure_renegotation_supported": false,
            "secure_renegotation": null,
            "extended_master_secret": false,
            "alpn_protocols": [
              "h2"
            ],
            "scts": true,
            "supported_versions": [
              772
            ],
            "early_data": false,
            "psk_modes": null,
            "psk_binders": null,
            "quic_transport_parameters": null,
            "encrypted_client_hello": null
          },
          "client_hello_inner": {
            "original": null,
            "vers": 771,
            "random": "iHvCndbRghQltxFWY9/5ThQKRNyDy89GnwqCNzky38c=",
            "session_id": "o3T3E0QG8qNdHa1r9yGaHmqkwvZcPntx0uaSt1bwv50=",
            "cipher_suites": [
              4867,
              4865,
              4866
            ],
            "compression_methods": "AA==",
            "server_name": "netd-research-one.de",
            "ocsp_stampling": true,
            "supported_curves": [
              25497,
              29,
              23,
              24,
              25
            ],
            "supported_points": null,
            "ticket_supported": false,
            "session_ticket": null,
            "supported_signature_algorithms": [
              2052,
              1027,
              2055,
              2053,
              2054,
              1025,
              1281,
              1537,
              1283,
              1539,
              513,
              515
            ],
            "supported_signature_algorithms_cert": null,
            "secure_renegotation_supported": false,
            "secure_renegotation": null,
            "extended_master_secret": false,
            "alpn_protocols": [
              "h2"
            ],
            "scts": true,
            "supported_versions": [
              772
            ],
            "early_data": false,
            "psk_modes": null,
            "psk_binders": null,
            "quic_transport_parameters": null,
            "encrypted_client_hello": null
          },
          "server_hello": {
            "original": "...",
            "vers": 771,
            "random": "iGAX38cgF6yer0AklmRn3yb0z4hKGf1VruYoENfzos8=",
            "session_id": "o3T3E0QG8qNdHa1r9yGaHmqkwvZcPntx0uaSt1bwv50=",
            "cipher_suite": 4867,
            "compression_method": 0,
            "ocsp_stampling": false,
            "ticket_supported": false,
            "secure_renegotation_supported": false,
            "secure_renegotiation": null,
            "extended_master_secrete": false,
            "alpn_protocol": "",
            "scts": null,
            "supported_version": 772,
            "selected_identity_present": false,
            "selected_identity": 0,
            "supported_points": null,
            "encrypted_client_hello": null,
            "server_name_ack": false,
            "selected_group": 0
          }
        }
      ],
      "timestamp": "2025-06-03T10:36:03+02:00"
    }
  }
}
```
