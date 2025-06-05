# ECH Module Scanner


> The ECH module can be used to scan domains/IPs and detect EncryptedClientHello Endpoints.
More specifically, this module tries to identify whether a given domain/IP hosts some service that is capable of establishing an EncryptedClientHello extension as speficied in [Draft-ietf-tls-esni-24](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

## Scanner workflow

The scanner imitates an ECH enabled client by supplying a correct/valid ECH configuration during the TLS handshake in the ClientHello message. Based on the specified options the scanner opens a network connection (TCP/UDP-Quic) to the target and tries to establish a TLS connection (waits at least until the handshake is finished, or the handshake gets aborted). 

Should the server accept the EncryptedClientHello, the target is marked as _enabled_ and meta-data about the connection is written, such as the __ClientHelloOuter__, the __ClientHelloInner__, and the __ServerHello__. In addition the used __ECH Config__, the targets IP address are logged in the same record.

Should the server indicate ECH rejection but provides __RetryConfigs__ through the _EncryptedExtions_ (part of the TLS specification), the scanner will parse these retry configs and perform a second attempt with the first retry config. Logging of data is the same as before with the addition of logging all retry configs returned by the server.

In the case of any TLS abortion or any other network related errors, the target is marked as _failed_ and no record is logged.

## Measuring TLS handshake latency

In addition to detecting enabled ECH deployments, the scanner can be instructed to measure the time the TLS handshake took. When enabled, an additional network connection of the same protocol is made before the ECH connection. This prior connection has neither a valid nor a _GREASE ECH_ configuration supplied and is used as anchor for comparison. 

Observation of latency measurements have shown that the initial connection might be biased by network related effects such as caching or else. This can result in an unintentionally increased latency for the inital connection. Observation shows, that this bias is independed of what the initial connection is, and for both ECH connection or non-ECH connection this bias has been observed. To mitigate the bias the scanner accepts a `--conn-primer` flag which specifies a network connection to the target. The primer can be a _tcp_ connection, a _tls_ connection, or a _dns_ query. No information from the primer function is logged but each successful record will indicate which primer was used (none is the default).


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

### Deploying the scanner
The scanner can be deployed using the `deploy` or `deploy-grease` make target. Both require a `USER` argument which is the __ssh user__ to use for copying the executable. By default the executable is build for a __linux/amd64__ arch with `ech.research.netd.cs.tu-dresden.de` as the target host. The target host can be changed by supplying the make target with a `HOST` argument.

## Results

The following shows the result for the above command with latency measurements enabled.
the `data.ech.result` is arranged as list and includes as many connection details as specified protocols (in this case only one for _h2_).

Each result contains all relevant data for tuple (target,protocol), such as the used ECH config, connection metadata, the ClientHelloOuter, ClientHelloInner and ServerHello. 



This will produce a `processed.parquet` file you can directly read from polars
```json

{
  "domain": "...",
  "data": {
    "ech": {
      "status": "success",
      "protocol": "ech",
      "result": [
        {
          "timestamp": "2025-06-03T14:23:47.320919+02:00",
          "domain": "...",
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
            "server_name": "...",
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

### Post Processing of the results

Included in the repository is the `processing.py` script which takes the zgrab2 output and converts it into a polars dataframe (parquet).
Sinze json to polars dataframe works..it only does so until a certain size. Therefore, the script chunks the input file into smaller pieces, parsing each piece, converting it into parquet and finally concatinating all chunks into a single dataframe. When you are reading this and think "this is stupid", I agree and would be more than happy if you have a better approach! :).

The resulting dataframe contains connection details per row. This means a scan with two protocols over 100 domainswill produce a dataframe with 200 rows. 100 rows for protocol one, and 100 rows for the second one.

To start the processing run:
```bash
$ python3 processing.py <zgrab2-results> <chunk-size:default 1000>
```

__Note:__ The processing script can be called with an uncompressed (raw) zgrab2 results file or an zstandard compressed file, in which case the file name __must__ end with `.zst`

## Adding protocols

The ECH module can be extended with different protocols by adding a new `proto_<name>.go` file with some struct that for your protocol that needs to implement the `ProtoTester` interface.

If for example we want to add HTTPS as an additional protocol we can do the following:
```go
// modules/ech/proto_https.go
package ech

type ProtoHTTPS struct {
    tlsCfg *ftls.Config
}


func (https ProtoHTTPS) Test(target string, measureLatency bool) (*ConnDetails, error) {

    var details ConnectionDetails
    // write the used ECH config into the scanner result
    details.populateECHConfig(https.tslCfg.EncryptedClientHelloConfigList)

    url := fmt.Sprintf("https://%s/cdn-cgi/trace", target)
    
    resp, err := http.Get(url)
    if err != nil {
      return nil, err
    }
    defer resp.Body.Close()

    // read + parse response body
    cgiFlags := parse(resp.Body)

    // note this function does not exist and one would need to extend the ConnDetails
    // if required.
    details.populateCGIFlags(cgiFlags)
    
    return details, nil
}
```


In the `modules/ech/scanner.go` you need to add your protocol to the `ProtoIter` such that it will be used.

```go
var protoIter = newProtoIter(s.config.MeasureHandshakeLatency)

for _, proto := range s.protos {
	switch proto {
	case "h1":
        // ...
	case "h2":
        // ...
	case "h3":
        // ...
    case "https":
        protoIter.Append(&ProtoHTTPS{
            tlsConfig: ftls.Config{
                ServerName: targetStr,
                EncryptedClientHelloList: targetConfig.preferneceListRaw
            },
        })
	default:
		log.Warnf("unrecogniced protocol provided: don't know: %q\n", proto)
	}
}
``
