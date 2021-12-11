import socket
from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.


    # Make the header in a similar way to the ping exercise.
    myID = os.getpid() & 0xFFFF  # Return the current process id

    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # Append checksum to the header.
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    # type, code, checksum, ID, seq number
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    # Don’t send the packet yet , just return the final packet in this function.
    # Fill in end

    # So the function ending should look like this

    packet = header + data

    return packet


def get_route(hostname):
    print("in get_route")

    timeLeft = TIMEOUT
    tracelist1 = []  # This is your list to use when iterating through each trace
    tracelist2 = []  # This is your list to contain all traces

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            print("we're in the nested for loop")
            destAddr = gethostbyname(hostname)

            # Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:

                d = build_packet()


                mySocket.sendto(d, (destAddr, 0))
                print("just sent socket to dest: ", destAddr)
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("* * * Request timed out.")
                    tracelist1.append("* * * Request timed out.")
                    # Fill in start
                    # You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    tracelist1.clear()  # clear out list for next packet
                    # Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                print("rec packet addy: ", addr[0])
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("* * * Request timed out.")
                    tracelist1.append("* * * Request timed out.")
                    # Fill in start
                    # You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    tracelist1.clear()  # clear out list for next packet
                    # Fill in end
            except timeout:
                print("about to continue to else statement")
                continue

            else:
                # Fill in start
                # Fetch the icmp type from the IP packet
                icmpHeader = recvPacket[20:28]

                types, code, checksum, hostID, sequence = struct.unpack("bbHHh", icmpHeader)  # unpacking the received header

                # Fill in end
                try:  # try to fetch the hostname
                    # Fill in start
                    # converting host ID from header to hostname

                    print(types, ", ", code, ", ", checksum, ", ", hostID, ", ", sequence)
                    print("fetching hostname")
                    hostname = gethostbyaddr(addr[0])
                    print("hostname is: ")
                    print(addr)
                    # Fill in end
                except herror:  # if the host does not provide a hostname
                    # Fill in start
                    hostname = "hostname not returnable"
                    # Fill in end

                if types == 11:
                    print("in type 11 if statement")
                    # type 11 = TTL field is 0 - router sends warning msg to source containing name of router and IP address
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    rtt = (timeReceived-timeSent)
                    print("rtt = ", rtt)
                    tracelist1.extend([ttl, " ", rtt, " ms ", addr[0], " ", hostname])
                    print("about to print tracelist1")
                    for x in range(len(tracelist1)):
                        print(tracelist1[x])
                    print("done printing tracelist1")

                    tracelist2.append(tracelist1)
                    # You should add your responses to your lists here

                    # Fill in end
                elif types == 3:
                    print("in type 3 if statement")
                    # type 3 = datagram arrives at dest and contains unlikely port #, so destination host sends a
                    # port unreachable ICMP message to the source
                    # source host now knows not to send any additional probe packets    `   ¸
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should add your responses to your lists here
                    rtt = (timeReceived - timeSent)
                    tracelist1.extend([ttl, rtt, addr[0], hostname])
                    tracelist2.append(tracelist1)

                    # Fill in end
                elif types == 0:
                    print("in type 0 if statement")
                    # type 0 = final destination received ICMP Echo Request = Echo Reply
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should add your responses to your lists here and return your list if your destination IP is met
                    rtt = (timeReceived - timeSent)
                    tracelist1.extend([ttl, rtt, addr[0], hostname])
                    tracelist2.append(tracelist1)
                    if (addr[0] == destAddr):
                        return tracelist2

                    # Fill in end
                else:
                    print("in else statement")
                    # Fill in start
                    # If there is an exception/error to your if statements, you should append that to your list here
                    tracelist1.append("*")
                    tracelist2.append(tracelist1)
                    # Fill in end
                return tracelist2
            finally:
                mySocket.close()

#get_route("google.com")
