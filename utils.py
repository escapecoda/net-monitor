import time
import ntplib
import requests
import string
import random
import zlib
import threading
import struct
import socket
import os
import time
import requests
import dns.resolver
import dns.exception
from socket import gaierror
from time import ctime
from typing import Tuple, Optional, Any

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
    # complement the result
    checksum = ~checksum & 0xffff

    return checksum
