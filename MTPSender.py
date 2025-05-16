## The code provided here is just a skeleton that can help you get started
## You can add/remove functions as you wish

import socket
import sys
import struct
import zlib
import threading
import time
import unreliable_channel

# Constants
DATA_PACKET = 0
ACK_PACKET = 1
HEADER_SIZE = 16  # 4 bytes each: type, seqNum, length, checksum
MAX_DATA_SIZE = 1472 - HEADER_SIZE  # MTU size - IP - UDP - MTP header
TIMEOUT = 0.5  # 500ms

# Global variables
window_size = 0
window_base = 0
next_seq_num = 0
packets = []
dup_ack_count = {}
timer = None
sender_socket = None
receiver_addr = None
log_file = None

# Lock for thread safety
lock = threading.Lock()

def create_packet(seq_num, packet_type, payload=b''):
    """Create an MTP packet with header and data"""
    # Create header fields
    type_field = packet_type.to_bytes(4, byteorder='big')
    seq_field = seq_num.to_bytes(4, byteorder='big')
    length_field = len(payload).to_bytes(4, byteorder='big')
    
    # Calculate checksum
    header_no_checksum = type_field + seq_field + length_field
    checksum = zlib.crc32(header_no_checksum + payload) & 0xFFFFFFFF
    checksum_field = checksum.to_bytes(4, byteorder='big')
    
    # Assemble packet
    packet = header_no_checksum + checksum_field + payload
    
    return packet

def extract_packet_info(packet):
    """Extract information from a received packet"""
    try:
        # Try to handle corruption where "corrupted!" is added to the end
        if isinstance(packet, bytes) and len(packet) >= HEADER_SIZE:
            # Check if packet might be corrupted with the "corrupted!" string
            if packet.endswith(b"corrupted!"):
                # Mark as corrupted
                return 0, 0, 0, 0, 0, b'', True
            
            # Extract header fields
            packet_type = int.from_bytes(packet[0:4], byteorder='big')
            seq_num = int.from_bytes(packet[4:8], byteorder='big')
            length = int.from_bytes(packet[8:12], byteorder='big')
            checksum_in_packet = int.from_bytes(packet[12:16], byteorder='big')
            
            # Extract data based on the length in the header
            data = packet[HEADER_SIZE:HEADER_SIZE+length]
            
            # Calculate checksum for verification
            header_no_checksum = packet[0:12]
            checksum_calculated = zlib.crc32(header_no_checksum + data) & 0xFFFFFFFF
            
            # Check if packet is corrupt
            is_corrupt = checksum_calculated != checksum_in_packet
            
            return packet_type, seq_num, length, checksum_in_packet, checksum_calculated, data, is_corrupt
        else:
            return None
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return None

def log_event(message):
    """Write message to log file and stdout"""
    global log_file
    log_file.write(message + '\n')
    log_file.flush()
    print(message)

def start_timer():
    """Start timeout timer"""
    global timer
    if timer:
        timer.cancel()
    timer = threading.Timer(TIMEOUT, handle_timeout)
    timer.daemon = True
    timer.start()

def handle_timeout():
    """Handle timeout event"""
    global window_base, window_size
    
    with lock:
        if window_base >= len(packets):
            return  # All packets ACKed
        
        log_event(f"Timeout for packet seqNum={window_base}")
        
        # Retransmit all packets in window
        end = min(window_base + window_size, len(packets))
        for i in range(window_base, end):
            send_packet(i)
        
        # Restart timer
        start_timer()

def log_window_state():
    """Log current window state"""
    global window_base, window_size, packets, next_seq_num
    
    if window_base >= len(packets):
        return
    
    window_end = min(window_base + window_size, len(packets))
    window_state = []
    
    for i in range(window_base, window_end):
        # 0: sent but not ACKed, 1: not sent
        status = 0 if i < next_seq_num else 1
        window_state.append(f"{i}({status})")
    
    window_str = ", ".join(window_state)
    log_event(f"Window state: [{window_str}]")

def send_packet(seq_num):
    """Send a packet with given sequence number"""
    global packets, sender_socket, receiver_addr
    
    if seq_num >= len(packets):
        return False
    
    packet = packets[seq_num]
    
    # Get packet info for logging
    packet_type, seq_num_from_packet, length, checksum_in_packet, _, _, _ = extract_packet_info(packet)
    
    # Send using unreliable channel
    unreliable_channel.send_packet(sender_socket, packet, receiver_addr)
    
    log_event(f"Packet sent; type=DATA; seqNum={seq_num_from_packet}; length={length}; checksum={checksum_in_packet:08x}")
    return True

def receive_thread():
    """Thread to handle received ACKs"""
    global window_base, window_size, packets, next_seq_num, dup_ack_count, sender_socket
    
    while window_base < len(packets):
        try:
            # Receive packet using unreliable channel
            packet, _ = unreliable_channel.recv_packet(sender_socket)
            
            # Extract packet info
            result = extract_packet_info(packet)
            
            # Ignore corrupt packets
            if result is None or result[6]:
                continue
            
            packet_type, seq_num, length, checksum_in_packet, checksum_calculated, _, _ = result
            
            # Log received packet
            if packet_type == ACK_PACKET:
                log_event(f"Packet received; type=ACK; seqNum={seq_num}; length={length}; "
                        f"checksum_in_packet={checksum_in_packet:08x}; "
                        f"checksum_calculated={checksum_calculated:08x}; "
                        f"status={'CORRUPT' if result[6] else 'NOT_CORRUPT'}")
            
            # Handle ACK packets
            if packet_type == ACK_PACKET and not result[6]:
                with lock:
                    # Handle duplicate ACKs
                    if seq_num < window_base:
                        if seq_num not in dup_ack_count:
                            dup_ack_count[seq_num] = 1
                        else:
                            dup_ack_count[seq_num] += 1
                        
                        # Triple duplicate ACK fast retransmit
                        if dup_ack_count[seq_num] == 3:
                            log_event(f"Triple dup acks received for packet seqNum={seq_num}")
                            
                            # Retransmit all packets in window
                            end = min(window_base + window_size, len(packets))
                            for i in range(window_base, end):
                                send_packet(i)
                            
                            # Reset timer
                            start_timer()
                    
                    # Process in-order ACK
                    elif seq_num >= window_base:
                        # Advance window
                        old_window_base = window_base
                        window_base = seq_num + 1
                        
                        log_event(f"Updating window; (seq_num={seq_num}, window_base={window_base})")
                        
                        # Clear duplicate ACK counters
                        for i in range(old_window_base, window_base):
                            if i in dup_ack_count:
                                del dup_ack_count[i]
                        
                        # Send more packets if available
                        new_end = min(window_base + window_size, len(packets))
                        for i in range(next_seq_num, new_end):
                            send_packet(i)
                            next_seq_num = i + 1
                        
                        # Log window state
                        log_window_state()
                        
                        # Restart timer if needed
                        if window_base < len(packets):
                            start_timer()
                        else:
                            if timer:
                                timer.cancel()
        
        except socket.timeout:
            continue  # Skip timeout to handle keyboard interrupts
        except Exception as e:
            print(f"Error in receive thread: {e}")
            continue

def main():
    global window_size, window_base, next_seq_num, packets, sender_socket, receiver_addr, log_file
    
    # Check command line arguments
    if len(sys.argv) != 6:
        print("Usage: ./MTPSender.py <receiver-IP> <receiver-port> <window-size> <input-file> <sender-log-file>")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    receiver_port = int(sys.argv[2])
    window_size = int(sys.argv[3])
    input_file = sys.argv[4]
    log_filename = sys.argv[5]
    
    # Store receiver address
    receiver_addr = (receiver_ip, receiver_port)
    
    # Open log file
    try:
        log_file = open(log_filename, 'w')
    except IOError as e:
        print(f"Error opening log file: {e}")
        sys.exit(1)
    
    # Create UDP socket
    try:
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender_socket.settimeout(0.1)  # Short timeout for keyboard interrupts
        log_event(f"Sender socket created")
    except socket.error as e:
        log_event(f"Socket error: {e}")
        sys.exit(1)
    
    # Read input file and create packets
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
            
            # Segment data into packets
            for i in range(0, len(data), MAX_DATA_SIZE):
                chunk = data[i:i+MAX_DATA_SIZE]
                packet = create_packet(len(packets), DATA_PACKET, chunk)
                packets.append(packet)
            
            log_event(f"Input file read and segmented into {len(packets)} packets")
    except IOError as e:
        log_event(f"Error reading input file: {e}")
        sys.exit(1)
    
    # Start receive thread
    recv_thread = threading.Thread(target=receive_thread)
    recv_thread.daemon = True
    recv_thread.start()
    
    # Reset for sending
    window_base = 0
    next_seq_num = 0
    
    # Send initial window of packets
    end = min(window_size, len(packets))
    for i in range(end):
        send_packet(i)
        next_seq_num = i + 1
    
    # Start timer
    start_timer()
    
    # Log initial window state
    log_window_state()
    
    # Wait for all packets to be acknowledged
    try:
        while window_base < len(packets):
            time.sleep(0.1)  # Prevent CPU hogging
    except KeyboardInterrupt:
        log_event("Transfer interrupted by user")
    
    # Clean up
    if timer:
        timer.cancel()
    sender_socket.close()
    log_file.close()
    
    print(f"File transfer complete. Sent {len(packets)} packets.")

if __name__ == "__main__":
    main()