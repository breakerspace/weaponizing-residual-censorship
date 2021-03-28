# weaponizing-residual-censorship [![RORR](https://img.shields.io/badge/IEEE%20Results%20Reproduced-PASSED-green.svg)](https://shields.io/) [![ORO](https://img.shields.io/badge/IEEE%20Open%20Research%20Objects-PASSED-green.svg)](https://shields.io/) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Repository for scripts for the WOOT 2021 paper: "Your Censor is My Censor: Weaponizing
Censorship Infrastructure for Availability Attacks".

## 📝 Abstract

Nationwide Internet censorship threatens free and open access to communication and information
for millions of users living inside of censoring regimes. In this paper, we show that this poses
an even greater threat to the Internet than previously understood. We demonstrate an attack that
exploits a little-studied but widespread feature of many censoring infrastructures: what we call
_residual censorship_, in which a censor continues blocking traffic between two end-hosts for some
time after a censorship event. Our attack sends spoofed packets with censored content, keeping
two victim end-hosts separated by a censor from being able to communicate with one another.
Although conceptually simple, this attack has several challenges, which we address. We
demonstrate the feasibility of the attack through two studies: one to capture the current state
of residual censorship, and another to actually launch the attack (against machines we control).
We show that the attack can be launched despite stateful TCP tracking used by many censors, and
that it also works against those who censor by null-routing. Our code is publicly available.

## ⚠️ Disclaimer 

These scripts will _intentionally_ trigger censorship responses with malformed or
non-protocol-compliant packet sequences that are detectable on the network. These scripts do not
provide any anonyminity. Understand the risks of testing them before doing so.

## 🏃 Try it

There are two scripts in this repository: one for triggering and identifying residual censorship
and a second to launch this attack from a source spoofed attacker.

Note that to prevent abuse, this code is *not* useful to launch this attack at scale: these
scripts are for testing small-scale attacks and to reproduce the results in our paper.

### 🏗 Set up

Just install the dependencies and you're good to go. 
```
python3 -m pip install -r requirements.txt
```

Before using the residual censorship scanner script, ensure that outbound `RST` packets are
being dropped. You can use the `drop_outbound_rsts.sh` script for this. 

### 🕵️ Identifying Abuseable Residual Censorship

The `residual_censorship_scanner.py` script is used to identify abusable four-tuple residual
censorship (null-routing). The script is designed to be run from a client (located either inside
or outside a censored regime) to an echo server located on the other side of the censor.

The script attempts to trigger censorship statelessly (without properly completing a 3-way
handshake), and then sends various follow-up test packets and checks if the server gets them. In
total, it performs 6 tests; if all six pass, the censorship system is likely abusable. If some
tests fail, it is possible the censorship system is not abuseable, or that the script is simply
running in an unexpected environment and needs modification.

The script is designed specifically for an echo server on one side, and expects a censor that
performs four-tuple null-routing censorship.

Before running, ensure outbound `RST` packets are being dropped, as they can interfere with the script.
You can use the provided `drop_outbound_rsts.sh` script for this.

```
$ python3 residual_censorship_scanner.py --help                      
usage: residual_censorship_scanner.py [-h] [--host HOST] [--protocol {http,https}] [--sleep-time SLEEP_TIME] [--skip-live-check]
                                      [--determine-duration] [--start-duration START_DURATION] [--num-test-packets NUM_TEST_PACKETS]
                                      server_ip server_port

4-tuple Residual Censorship Detection Script

positional arguments:
  server_ip             The IP address of the echo server
  server_port           The port of the echo server

optional arguments:
  -h, --help            show this help message and exit
  --host HOST
  --protocol {http,https}
  --sleep-time SLEEP_TIME
                        Sleep time between sending the forbidden query and test packets
  --skip-live-check     Skip the echo server liveliness check.
  --determine-duration  Instead of running the normal battery of tests, run the duration test.
  --start-duration START_DURATION
                        Number of seconds to start at for duration determinations.
  --num-test-packets NUM_TEST_PACKETS
                        Number of test packets to send.
```

Example:
```
$ sudo python3 residual_censorship_scanner.py <ip address> 7 --host avaaz.org
...
Summary:
- 3-way handshake, tested with a well-formed innocuous query on PSH+ACK packet, with a good seqno/ackno: censored.
- 3-way handshake, tested with a malformed innocuous query on PSH+ACK packet, with a good seqno/ackno: censored.
- No 3-way handshake, tested with a well-formed innocuous query on PSH+ACK packet, with a good seqno/ackno: censored.
- 3-way handshake, tested with a SYN packet, with a good seqno/ackno: censored.
- No 3-way handshake, tested with a SYN packet, with a good seqno/ackno: censored.
- No 3-way handshake, tested with a SYN packet, with a different seqno/ackno: censored.
Abusable residual censorship detected.
```

This script can also be used to determine the duration of time residual censorship lasts with `--determine-duration`.


### 🚀 Source IP Address Spoofing: Launching the Attack

To test launching the attack against yourself, you can use `sp3_send.py`. This relies on a
public instance of the amazing (SP)^3 project (see https://github.com/willscott/sp3). SP3 is a
service that allows a client to _consent_ to receiving spoofed traffic. If you set up a
different SP3 server yourself, you can override the default and use that; otherwise, you can use
the default public instance of SP3 located in the University of Washington.

To use this script to test the attack, you must use it from a machine located inside a censored
regime (this is because this attack relies on the attacker and victim being on the same side of
the censor, and SP3 is located in the United States). When you run the script, that machine will
connect to SP3 with a websocket connection to consent to receiving spoofed traffic and then give
SP3 packets to send to it. By controlling the source address of those packets to a machine you
control, you can ethically test if this attack could feasibly block communication between your
two IP addresses.

Note that to prevent abuse, this script will only trigger censorship for a single given source
port. To test if the resulting four-tuple residual censorship is affecting you, you can give SP3
a specific source port and then use `curl` with `--local-port`, such as: `curl <ip-address-of-machine-in-censored-regime>:<port> --local-port 22222`.

The script supports four different payloads to send with: a forbidden HTTP request, HTTPS
request (youporn in the SNI field), an ESNI request, and a series of malformed bytes.

```
$ python3 sp3_send.py --help                                                              [16:49:46]
usage: sp3_send.py [-h] [--public-ip PUBLIC_IP] --victim-ip VICTIM_IP [--protocol {http,https,malformed,esni}] [--sport SPORT]
                   [--perform-sp3-traceroute] [--sp3 SP3]

SP3 Spoofing Script

optional arguments:
  -h, --help            show this help message and exit
  --public-ip PUBLIC_IP
                        IP address of this computer
  --victim-ip VICTIM_IP
                        IP address of victim computer (who traffic should be spoofed as)
  --protocol {http,https,malformed,esni}
                        payload protocol to send with.
  --sport SPORT         source port to use
  --perform-sp3-traceroute
                        instead of launching the attack, perform an sp3 traceroute
  --sp3 SP3             The URI IP:port of the sp3 server
```

## 👷 Contributors
 
[Kevin Bock](https://www.cs.umd.edu/~kbock/)

[Pranav Bharadwaj](https://github.com/pbokc)

[Jasraj Singh](https://github.com/jasrajsingh1)

[Dave Levin](https://www.cs.umd.edu/~dml/)

[Will Scott](https://github.com/willscott)

We would also like to thank IEEE's anonymous Artifact Evaluators for their time, effort, and dilligence in exercising these artifacts for the WOOT Artifact Evaluation. 
