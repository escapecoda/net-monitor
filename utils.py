import statistics
import string
import socket
import socketserver
import dns.exception
import dns.resolver
import ntplib
import os
import random
import socket
import string
import requests
import struct
import threading
import time
import zlib
from socket import gaierror
from time import ctime
from typing import Tuple, Optional, Any

# Third party library
import requests

def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum
    """
    checksum: int = 0

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes
        word: int = (data[i] << 8) + (data[i + 1])
        checksum += word # Add the 16-bit word to the sum.

    # add the overflow back into the sum
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff

    return checksum


def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0,
                       sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payloud in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet conbining the specified
    ICMP type, code, and sequence number with a  data payload of a specified
    size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id: int = threading.get_ident()
    process_id: int = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It is a sequence of a single randomly chosen alphanumeric characters (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    checksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in the network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(checksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data


def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Tuple[Any, float] | Tuple[Any, None]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceedd before receiving a reply, the function returns None for the pine time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in milliseconds.
    If the request times out, the function returns None for the ping time. the address part of the tuple is also None if no reply is received.
    """

    # Create a raw socket with the Internet Protocll (IPv4) and ICMP.
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_RAW allows sending raw packets (including IMCP).
    # socket.IPROTO_ICMP specifies the ICMP protocol.
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_ICMP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blcokig operations (e.g., recvfrom).
        # icmp_type=8 and icmp_code=0 are standard for an Echo Request
        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        # The second argument of sendto is a tuple (host, port)
        # For raw sockets, the port number is irrelavent, hence set to 1.
        sock.sendto(packet, (host, 1))

        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time: float = (end - start) * 1000

            # Return the address of the replier and the total ping tme.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None


def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """

    # Header row for the results. Each column is formatted for alignment and width.
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8} {'Avg (ms)':>8} {'Max (ms)':>8} {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for current TTL
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            # The sequence number is incremented with TTL for each ping.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times
            if response is not None:
                ping_times.append(response)

        # if there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)
            avg_time = sum(ping_times) / len(ping_times)
            max_time = max(ping_times)
            count = len(ping_times)

            # Append the formatted results for this TTL to the results list.
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms {max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8} {'*':>8} {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute
        if addr and addr[0] == host:
            break

    return '\n'.join(results)


def check_server_http(url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the servre (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """

    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code

    except requests.RequestException:
        # This block catches any excption that might occur during the request.
        # This includes network problems, invalid URL, etc.
        # If an exception occurs, we assme the server is down.
        # Returning False for the status, and None for the status code,
        # as we couldn't successfully connect to the server to get a status code.
        return False, None


def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # Time timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised ofr network-related errors, like DNS failure or refused connection.
        return False, None, "Connection Error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the alloted time (specified by timeout)
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A cathc-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"


def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                (True if up, False if down) and the current time as a string
                                if the server is up, or None if it's down.
    """
    
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If the request is successful, return True and the server time.
        # 'ctime' converts the time in seconds since the epoch to a readable format.
        return True, ctime(response.tx_time)

    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None


def check_dns_server_status(server: str, query: str, record_type: str) -> Tuple[bool, str]:
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    Args:
    server (str): DNS server name or IP address
    query (str): Domain name to query
    record_type (str): Type of DNS record (e.g. 'A', 'AAA', 'MX', 'CNAME')

    Returns:
    Tuple[bool, str]: A tuple containing a boolean indicatin the server status and query results
                      (True if up, False if down) and the query results as a string.
    """
    try:
        # Set the DNS resolver to use the specified server.
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameServers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)


# Ping Usage Example
print("Ping Example")
ping_addr, ping_time = ping("8.8.8.8")
print(f"Google DNS (ping): {ping_addr[0]} - {ping_time:.2f} ms" if (ping_addr and ping_time is not None) else "Google DNS (ping): Request timed out or no reply received")

# Traceroute Usage Example
# Note: This function is included as an extra to round out the ICMP examples.
print("\nTraceroute Example")
print("Google DNS (traceroute)")
print(traceroute("8.8.8.8", verbose=True))
