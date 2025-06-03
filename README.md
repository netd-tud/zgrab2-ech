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

### Post Processing of the results

Included in the repository is the `processing.py` script which takes the zgrab2 output and converts it into a polars dataframe (parquet).
Sinze json to polars dataframe works..it only does so until a certain size. Therefore, the script chunks the input file into smaller pieces, parsing each piece, converting it into parquet and finally concatinating all chunks into a single dataframe. When you are reading this and think "this is stupid", I agree and would be more than happy if you have a better approach! :).

To start the processing run:
```bash
$ python3 processing.py <zgrab2-results> <chunk-size:default 1000>
```

This will produce a `processed.parquet` file you can directly read from polars
```json

{
  "domain": "tartetryon.com",
  "data": {
    "ech": {
      "status": "success",
      "protocol": "ech",
      "result": [
        {
          "timestamp": "2025-06-03T14:23:47.320919+02:00",
          "domain": "tartetryon.com",
          "protocol": "tcp",
          "conn_primer": "dns",
          "error": null,
          "ech_version": 65037,
          "ech_config_id": 186,
          "ech_public_name": "cloudflare-ech.com",
          "ech_kem_name": 32,
          "ech_config_len": 1,
          "ech_cipher_suites": [
            "{(cipher) kdf: SHA256, aead: AES128GCM}"
          ],
          "ech_max_name_len": 0,
          "ech_raw_extensions": "",
          "alpn_list": [
            "h3",
            "h2"
          ],
          "ipv4_hints": [
            "162.159.140.118",
            "172.66.0.116"
          ],
          "ipv6_hints": [
            "2606:4700:7::75",
            "2a06:98c1:58::75"
          ],
          "ip": "172.66.0.116",
          "transport": "tcp",
          "tls_version": "TLS 1.3",
          "tls_handshake_duration_with_ech": 20,
          "tls_handshake_duration_without_ech": 14,
          "tls_handshake_anchor_ip": "172.66.0.116",
          "accepted_ech": true,
          "tls_handshake_completed": true,
          "negotiated_protocol": "h2",
          "negotiated_cipher": "TLS_CHACHA20_POLY1305_SHA256",
          "retry_configs": null,
          "client_hello_outer": {
            "original": null,
            "vers": 771,
            "random": "/wlB9DYFe2NO6rSAEnxLJYMapuj0DKJf3m8opnW0yy8=",
            "session_id": "GHlHiaaBG/J06gZ5lKnH2yuF+5YVVZBB1k0xHyMu3uw=",
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
            "random": "nNvTLBHl/z7CjAh023pt1Yrd7vAeDeo+p7v00sG8Ep4=",
            "session_id": "GHlHiaaBG/J06gZ5lKnH2yuF+5YVVZBB1k0xHyMu3uw=",
            "cipher_suites": [
              4867,
              4865,
              4866
            ],
            "compression_methods": "AA==",
            "server_name": "tartetryon.com",
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
            "original": "AgAEtgMD/Te0qOj6ChSPYGxrPml7Nw+uPCpkDbt51lwEO+ivVVUgGHlHiaaBG/J06gZ5lKnH2yuF+5YVVZBB1k0xHyMu3uwTAwAEbgAzBGRjmQRgRHsSLxcZGSGwXxYkFB5FLJDGN66H3gA3pgGO9c0DRWAp+h6EhXBx7Ik7IFdovQxncbepYAD+z8xl+UnRg6Zu/HXZzvdKgQtHDSEGIFNxQOmn/l2FeN4/lFBjwQ4geoqYfzhlFSTAMAZ9f7lLeNkE6e6BYVobBBKAPcV7LS2WpheJ0efhkowsft7wbaz4p9lq1wNGuLRvlqBsMn0UEX18ywpn8mLkjREIT3S9bLbMp2LKh8uZT92JoH1v4oWwizV59SSNMGTDZks0t3LVHy46muLr92p2eMo+rECFARtxU+Nh3jrJUcifes2MAqedmXjR7sQWZWcMtW56QmK0gBSlUMbt/LPhSANjUCLqGLvhQKz1fBYrqu0M5u8ZmqbpSpuJCLYtYPUVNQYF5GlaLiDxYMmsXdx/Cpd6vemH9ddPxUlTyXOgMAMfxnO35uMsznI3n5nvizQGcM6RFFmdV+EqEcF6SzC3u35z17IRybRsp2YtaL04CMA4b+1VawywIEYBF7greo6cq2D5WJcfh6kwoqv0JQodTVrZvlL1p77eS0Ns0c1r/vDwWPiRrVPNum7TbQWFzJ+PLNlXIbzJOeFYVxGqXw+mZvj1qq7ba9h6QPL3VJs9YGbeWk5QWhqijTBFyc5b7224LH/R+QkDXwTYigZM+iyBzFzMmmXDaJaiQEKzLGB2PEVkM/d9KRfnvM9QWhXm4aEA74X/+UbBHy7PhmIsSFSnKtuF9+cwvcEPLjcvlqtmcUMLzk83KKcbdWk/kWYQZK+nrfxK/pBoqjChpu8zijoaZ4RAefOLFL/fcgBbn1hM0ooxMxUqYhUGMa9jDhRWJHar5Zxe+9sv4Rf4cpp7lXvBGIyJ2AcdKuX+qwWvmnWgOAJPW5n0MM8T1fSHeL0tE21dEmA1GL3zwBkvpgaQTEKyHEF0SRv/UJTWEU02SSfDemCfr3+huWFJo4pP3eJbTotcq6zC7zaBMPz6pSVWalmd9+y6ewN9oabpR+oJr7ASPKiFnFj8eYQuwbOaxGZI+FDSMFtZJSIYKb1LSfy1oJYYhRVCXnBWhwjbGmBJTwcXi73QENrA10vBlnw45F+59TpgL7IngJ0zKd8yIho++ImKITs9M/djndppetvRmMhEZxC//IgtbinRzl/liYvpABV8M87hUf4B5z2YFZk55PUnckSQpE6ayZsyrFn7/iV0XAEQIvcFk0Lh5zmpSjJc6BL+XQFsIZAmrUMtD/etKKj5kZMKLxTVsNulqT+U+D9e7w3dH1kdd5FDCQ6hQq5wu8Afjwv9JL6Y+hvtyNeAfZU6E/+q2IHPvulyRX5MQT4G0J8mOO9oqQtHguDLggjtZ/bhqZbMIr4Xp5I8xfOOLd/e9G7h96OPxntE65J3FpaVqOMJpk+DNCMT1U8WA3nBmGUd3CfepBFOmFrQrKsoczPWM51g2umpX5EbrUFK+kt5hXyFm1NjVmKop/QhCHaXnJPnUEaiE55JYl9YLAArAAIDBA==",
            "vers": 771,
            "random": "/Te0qOj6ChSPYGxrPml7Nw+uPCpkDbt51lwEO+ivVVU=",
            "session_id": "GHlHiaaBG/J06gZ5lKnH2yuF+5YVVZBB1k0xHyMu3uw=",
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
      "timestamp": "2025-06-03T14:23:47+02:00"
    }
  }
}

```
