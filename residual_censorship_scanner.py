"""
Residual Censorship 

Script is used to detect the presence of residual censorship (typically from null-routing) 
to an echo server.
- Connect to the given echo server and send a test string to check that the server is responsive.
- Connect again and send a forbidden HTTP GET request. Wait a second, and then send a  

It makes a connection to the echo server to check that the server is up and responsive, and
then sends a potentially well-formed HTTP GET request with a forbidden URL in the Host: header.
Example: GET / HTTP/1.1\r\nHost: www.youporn.com\r\n\r\n
"""

import argparse
import binascii as bi
import colors
import copy
import random
import socket
import sys
import time

from scapy.all import *


def test_echo_server(dest_ip, dest_port):
    """
    Tests if the given echo server is responsive.

    Args:
        dest_ip (str): Destination IP address of an echo server on the other side of a censor
        dest_port (int): Destination port of an echo server on the other side of a censor
    
    Raises:
        RuntimeError: if the given echo server is not responsive or we encounter an unexpected error
    """
    print(colors.color("Checking echo server %s:%d for responsiveness..." % (dest_ip, dest_port), fg="yellow"), end="")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the echo server
            s.connect((dest_ip, dest_port))

            s.sendall(b"Testing")
            data = s.recv(1024)

            # Tests if data sent was the same as what was received. If not the dest_ip
            # is not an echo server and we bail.
            if data != b"Testing":
                raise RuntimeError("ERROR: Server %s:%d is not echo server" % (dest_ip, dest_port))
            s.close()
    # If we fail to connect or have some other failure, bail.
    except Exception as exc:
        raise RuntimeError("ERROR: Echo server %s:%d is not responsive." % (dest_ip, dest_port)) from exc

    print(colors.color(" done.", fg="green"))


def get_answer(answers, expected_flags="PA", expected_seqno=None, expected_ackno=None):
    """
    Helper script to parse through a list of potential answers to find the
    actual response packet we care about. Scapy normally does much of this
    checking for us when we use `sr`, but due to censorship, it's possible to
    receive multiple copies of the same packet or other unexpected packets.
    Args:
        answers (list): List of answer packets tuples from `sr`
        expected_flags (str, optional): TCP flags on the expected packet
        expected_seqno (int, optional): Sequence number on the expected packet
        expected_ackno (int, optional): Acknowledgment number on the expected packet
    """
    print("Parsing answer out of %d potential answers" % len(answers))
    for packet in answers:
        if not packet.haslayer("TCP"):
            print("Ignoring non TCP packet")
            continue
        if packet["TCP"].flags != expected_flags:
            print("Ignoring packet with unexpected flags:", packet.summary())
            continue
        if expected_seqno is not None and packet["TCP"].seq != expected_seqno:
            print("Ignoring packet with unexpected seqno %d (expected: %d)" % (packet["TCP"].seq, expected_seqno), packet.summary())
            continue
        if expected_ackno is not None and packet["TCP"].ack != expected_ackno:
            print("Ignoring packet with unexpected ackno %d (expected: %d)" % (packet["TCP"].ack, expected_ackno), packet.summary())
            continue
        return packet
    return None 


def three_way_handshake(dest_ip, dest_port, one_way=False):
    """
    Using scapy, perform a three-way handshake with the given dest_ip and dest_port.
    Args:
        dest_ip (str): Destination IP address of an echo server on the other side of a censor
        dest_port (int): Destination port of an echo server on the other side of a censor
        one_way (bool, optional): If the connection should be done one-sided. 
    Returns:
        tuple: source port, sequence number, ack number
    """
    # Choose a random number >10,000 for source port
    src_port = random.randint(10000, 65000)
    # Choose a random initial sequence number
    seqno = random.randint(100, 1000000)

    print("Starting 3-way handshake (source port %d)..." % src_port, end="")
    # Craft a SYN packet 
    syn = IP(dst=dest_ip) / TCP(dport=dest_port, sport=src_port, seq=seqno, flags="S")
    if one_way:
        send(syn, verbose=False)
        ackno = random.randint(100, 100000)
    else:
        # Send the SYN packet and receive the SYN+ACK from the server
        syn_ack = sr1(syn, verbose=False)  
        # Increment the destination's initial sequence number to get the starting acknowledgement number
        ackno = syn_ack["TCP"].seq + 1 

    # Increment the initial sequence number to complete the three-way handshake
    seqno = seqno + 1 

    # Craft the ACK packet to finish the three-way handshake
    ack = IP(dst=dest_ip)/TCP(dport=dest_port, sport=src_port, seq=seqno, ack=ackno, flags="A")
    send(ack, verbose=False)               

    print(" completed.")
    return src_port, seqno, ackno


def mysr(packet, host, src_port, timeout):
    """
    We'd like to use scapy's `sr` (send/receive) function for sending and receiving packets.
    Unfortunately, the matching algorithm for `sr` is not good enough for our uses, and will
    miss packets that we need to capture. For example, if the sequence number or acknowledgement
    number of a response does not match a packet we send, it will not be considered a response (even
    if this is exactly what you'd expect if the other side sent a `RST` packet).
    Instead, we use an AsyncSniffer to capture the traffic we're interested in.
    """
    sniffer = AsyncSniffer(filter="host %s and dst port %d" % (host, src_port), store=True, prn=lambda x: None)
    sniffer.start()
    send(packet, verbose=False)
    time.sleep(timeout)
    sniffer.stop()
    return sniffer.results 


def test_innocuous_query(dest_ip, dest_port, host_header="youporn.com", sleep_time=1, test_flags="PA", one_way=False, malformed_test_query=False, bad_seqack=False, protocol="http", num_test_packets=1, description="", **kwargs):
    """
    Connects to the echo server, sends a forbidden HTTP GET request, and then sends
    an innocuous request. Checks if the given response is
    Args:
        dest_ip (str): Destination IP address of an echo server on the other side of a censor
        dest_port (int): Destination port of an echo server on the other side of a censor
        host_header (str, optional): URL to put in the Host: header 
        sleep_time (int, optional): Duration of sleep between sending forbidden query and test packets.
        test_flags (str, optional): Type of packet to test with. Defaults to 'PA' for PSH+ACK. 
        one_way (bool, optional): If the connection should be done one-sided. 
        malformed_test_query (bool, optional): If the test data should be garbage. 
        bad_seqack (bool, optional): Whether the test data should be sent with a bad seqno and ackno
        protocol (str, optional): which protocol to test with
    """
    print(colors.color("Starting test %s" % description, fg='blue'))
    forbidden_query = b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host_header.encode('utf-8')
    # The hex bytes of an `openssl s_client -connect <ip>:<port> -servername youporn.com`
    if protocol == "https":
        forbidden_query = bi.unhexlify("16030101400100013c0303a6308d7e4350bbb358b2775fdc299883a29bf1bde3a61c3298f0ca18909434790000aac030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f00960041c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff0100006900000010000e00000b796f75706f726e2e636f6d000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101")
        
    innocuous_query = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    if malformed_test_query:
        innocuous_query = b"nonsense data"
    elif test_flags != "PA":
        innocuous_query = b""
    
    src_port, seqno, ackno = three_way_handshake(dest_ip, dest_port, one_way=one_way)

    print("Sending HTTP query...", end="")
    # Craft and send PSH+ACK packet containing the HTTP query 
    data_packet = (
        IP(dst=dest_ip)
        / TCP(dport=dest_port, sport=src_port, seq=seqno, ack=ackno, flags="PA")
        / Raw(forbidden_query)
    )
    send(data_packet, verbose=False)
    print(" sent.")

    # Since the echo server will send back the same data we sent it, 
    # we can update both the seqno and the ackno using the length of the http query.
    ackno = ackno + len(forbidden_query)
    seqno = seqno + len(forbidden_query) 

    # Acknolwedge the packet. This isn't strictly necessary (since we'll ack it
    # anyway if we send a PSH+ACK below), but it removes confusing
    # retransmissions if the sleep time is large.
    time.sleep(0.25)
    ack = IP(dst=dest_ip)/TCP(dport=dest_port, sport=src_port, seq=seqno, ack=ackno, flags="A")
    send(ack, verbose=False)

    print("Sleeping %d seconds before sending test packets." % sleep_time)
    time.sleep(sleep_time)

    for test_packet_num in range(num_test_packets):
        if bad_seqack:
            seqno = random.randint(100, 1000000)
            ackno = random.randint(100, 1000000)

        # Create a test packet with innocuous query
        data_packet = (
            IP(dst=dest_ip)
            / TCP(dport=dest_port, sport=src_port, seq=seqno, ack=ackno, flags=test_flags)
            / Raw(innocuous_query)
        )
        print("Sending a test packet to check for residual censorship (5s)...") 
        answers = mysr(data_packet, dest_ip, src_port, 5)
        # At this point, we may have multiple copies of the packets we care about:
        # pull out the one most likely to be the one we care about. First, figure out
        # the expected response from the server (assuming no censorship) given our test config
        expected_seqno = ackno
        expected_ackno = None
        if test_flags == "PA" and not one_way:
            expected_flags = "PA"
        elif test_flags == "PA" and one_way:
            expected_flags = "R"
            expected_seqno = ackno
        elif test_flags == "S" and one_way:
            expected_flags = "RA"
            expected_seqno = None
            expected_ackno = seqno + 1
        elif test_flags == "S" and not one_way:
            expected_flags = "A"
            expected_seqno = None
        answer = get_answer(answers, expected_flags=expected_flags, expected_seqno=expected_seqno, expected_ackno=expected_ackno)
        if answer:
            break

        seqno = seqno + len(innocuous_query)
        ackno = ackno + len(innocuous_query)

    rst_ack = IP(dst=dest_ip)/TCP(dport=dest_port, sport=src_port, seq=seqno, ack=ackno, flags="RA")
    print("Trying to close connection with a RST+ACK packet.")
    send(rst_ack, verbose=False)

    censorship_detected = False
    # If we got no response, this is likely 4-tuple null-routing censorship.
    if not answer:
        print("Received no matching answers.")
        censorship_detected = True 
    # If we got a response that matches our data, there is likely no residual censorship.
    elif answer.haslayer("Raw") and answer["Raw"].load == innocuous_query:
        censorship_detected = False
    # If we get a different payload, there is likely injected-content censorship.
    elif answer.haslayer("Raw") and answer["Raw"].load != innocuous_query:
        censorship_detected = True
        print("Warning: echo response %s did not match." % answer["Raw"].load)

    if censorship_detected:
        print(colors.color("Censorship detected.", fg="green"))
    else:
        print(colors.color("No censorship detected.", fg="red"))

    return censorship_detected



def run_tests(dest_ip, dest_port, options):
    """
    Takes in a dest IP and port of an echo server in the country where you want to 
    test for the existence of residual censorship and a forbidden query string. 
    Returns a boolean that represents whether or not 4 tuple residual censorship 
    was found. Prints further information about the data sent/recieved. 
    Args:
        dest_ip (str): Destination IP address of an echo server on the other side of a censor
        dest_port (int): Destination port of an echo server on the other side of a censor
        options (dict): Dictionary of options for this run. Options include:
            - host_header (str): URL to put in the Host: header 
            - sleep_time (int): Duration of sleep between sending forbidden query and test packets.
            - skip_live_check (bool): Whether the liveliness check should be skipped 
    
    Raises:
        RuntimeError: If the given echo server is not responsive.
    """
    sleep_time = options.get("sleep", 5)
    skip_live_check = options.get("skip_live_check")
    if not skip_live_check:
        # Check if the echo server is responsive. This will raise a RuntimeError if the server is down.
        test_echo_server(dest_ip, dest_port)

    tests = [
        {
            "description": "3-way handshake, tested with a well-formed innocuous query on PSH+ACK packet, with a good seqno/ackno",
        },
        {
            "malformed_test_query": True,
            "description": "3-way handshake, tested with a malformed innocuous query on PSH+ACK packet, with a good seqno/ackno",
        },
    
        {
            "one_way": True,
            "description": "No 3-way handshake, tested with a well-formed innocuous query on PSH+ACK packet, with a good seqno/ackno",
        },
        {
            "test_flags": "S",
            "description": "3-way handshake, tested with a SYN packet, with a good seqno/ackno", 
        }, 
        {
            "test_flags": "S",
            "one_way": True,
            "description": "No 3-way handshake, tested with a SYN packet, with a good seqno/ackno", 
        },
        {
            "test_flags": "S",
            "one_way": True,
            "bad_seqack": True,
            "description": "No 3-way handshake, tested with a SYN packet, with a different seqno/ackno", 
        },
    ]
    if options.get("determine_duration"):
        return test_duration(dest_ip, dest_port, options)

    # Run the tests
    for test in tests:
        test_options = copy.deepcopy(options)
        test_options.update(test)
        test["result"] = test_innocuous_query(dest_ip, dest_port, **test_options) 

    # Print a summary of the test results
    print(colors.color("\nSummary:", fg="green")) 
    for test in tests:
        print_test_result(test["result"], test["description"])

    if all([t["result"] for t in tests]):
        print(colors.color("Abusable residual censorship detected.", fg='green'))
    elif any([t["result"] for t in tests]):
        print(colors.color("Some residual censorship detected, but likely not abuseable.", fg='yellow'))
    else:
        print(colors.color("No residual censorship detected.", fg='red'))
        

def test_duration(dest_ip, dest_port, options):
    """
    Determines the duration of residual blocking.
    """
    censored = True
    sleep = options.get("start_duration", 5)
    # Remove the sleep_time key if it is present because we splat options into the method below
    options.pop("sleep_time", None)
    while censored and sleep <= 600:
        print(colors.color("Testing %ds:"% sleep, fg='blue'))    
        censored = test_innocuous_query(dest_ip, dest_port, sleep_time=sleep, bad_seqack=True, test_flags="S", description="Sleep %ds" % sleep, **options)

        if not censored:
            break
        sleep += 5
    else:
        print(colors.color("Warning: Did not find ceiling to censor's timer."))
    print("Approximate Duration: %d" % sleep)


def print_test_result(result, description):
    """
    Helper to pretty print test results.
    """
    print("- %s:" % description, end="")
    if result is None:
        print(colors.color(" not tested.", fg="red")) 
    elif result:
        print(colors.color(" censored.", fg="green")) 
    else:
        print(colors.color(" no censorship.", fg="red")) 


def get_args():
    """
    Sets up arg parsing.
    """
    parser = argparse.ArgumentParser(description="4-tuple Residual Censorship Detection Script")
    parser.add_argument("server_ip", type=str, help="The IP address of the echo server")
    parser.add_argument("server_port", type=int, help="The port of the echo server")
    parser.add_argument("--host", type=str, default="youporn.com")
    parser.add_argument("--protocol", type=str, default="http", choices=("http", "https"))
    parser.add_argument("--sleep-time", type=int, default=1, help="Sleep time between sending the forbidden query and test packets")
    parser.add_argument("--skip-live-check", action="store_true", help="Skip the echo server liveliness check.")
    parser.add_argument("--determine-duration", action="store_true", help="Instead of running the normal battery of tests, run the duration test.")
    parser.add_argument("--start-duration", type=int, default=0, help="Number of seconds to start at for duration determinations.")
    parser.add_argument("--num-test-packets", type=int, default=1, help="Number of test packets to send.")
    return parser.parse_args()


def main(args):
    # Test the given server for 4-tuple residual censorship.
    run_tests(args.server_ip, args.server_port, options=vars(args))


if __name__ == "__main__":
    main(get_args())
