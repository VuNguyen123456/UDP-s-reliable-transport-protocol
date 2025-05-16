# import socket
import random
# random.seed(42)
# These functions will be used to simulate an unreliable channel
# that can corrupt a packet while receiving it
# or drop a packet while sending it

# If you want to no drops or corruption (while starting to write your code)
# use
probability = 1
# else it can be anything < 1, test your code for different values
probability = 0.95

def recv_packet(socket):
    received_data, recv_addr = socket.recvfrom(1472)
    #corrupt the packet
    if random.random()>probability:
        if isinstance(received_data, str):
            received_data+="corrupted!"
        else:
            received_data += b"corrupted!"
    return received_data,recv_addr


def send_packet(socket,packet,recv_addr):
    #drop the packet 5% of the time
    if random.random()<probability:
        socket.sendto(packet,recv_addr)