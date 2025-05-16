## The code provided here is just a skeleton that can help you get started
## You can add/remove functions as you wish


import socket
import sys
import struct
import zlib
import threading
import unreliable_channel

# constants
DATA_PACKET = 0
ACK_PACKET = 1
HEADER_SIZE = 16  # 4 bytes each: type, seqNum, length, checksum
MAX_PACKET_SIZE = 1472  # MTU (1500) - IP header (20) - UDP header (8)
DELAYED_ACK_TIMEOUT = 0.5  # 500ms

# Global vars for state
expected_seq_num = 0
received_data = {}
pending_ack = None
delayed_ack_timer = None

def create_packet(seq_num, packet_type, payload=b''):
    """Create an MTP packet with header and data"""
    # create header fields
    type_field = packet_type.to_bytes(4, byteorder='big')
    seq_field = seq_num.to_bytes(4, byteorder='big')
    length_field = len(payload).to_bytes(4, byteorder='big')
    
    # calculate checksum
    header_no_checksum = type_field + seq_field + length_field
    checksum = zlib.crc32(header_no_checksum + payload) & 0xFFFFFFFF
    checksum_field = checksum.to_bytes(4, byteorder='big')
    
    # assemble packet
    packet = header_no_checksum + checksum_field + payload
    
    return packet

def extract_packet_info(packet):
    """Extract information from a received packet"""
    try:
        if len(packet) < HEADER_SIZE:
            return None, None, None, None, None, None, True
        
        # Extract header fields
        packet_type = int.from_bytes(packet[0:4], byteorder='big')
        seq_num = int.from_bytes(packet[4:8], byteorder='big')
        length = int.from_bytes(packet[8:12], byteorder='big')
        checksum_in_packet = int.from_bytes(packet[12:16], byteorder='big')
        
        # extract data
        data = packet[HEADER_SIZE:HEADER_SIZE+length]
        
        # Calculate checksum to verify
        header_no_checksum = packet[0:12]
        checksum_calculated = zlib.crc32(header_no_checksum + data) & 0xFFFFFFFF
        
        # Check if packet is corrupt
        is_corrupt = checksum_calculated != checksum_in_packet
        
        return packet_type, seq_num, length, checksum_in_packet, checksum_calculated, data, is_corrupt
    except Exception:
        # Any exception means corrupted packet
        return 0, 0, 0, 0, 0, b'', True

def log_event(log_file, message):
    """Write message to log file and stdout"""
    log_file.write(message + '\n')
    log_file.flush()
    print(message)

def send_ack(socket, seq_num, addr, log_file):
    """Send an ACK packet"""
    try:
        ack_packet = create_packet(seq_num, ACK_PACKET)
        
        # get packet info for logging
        packet_type, seq_num, length, checksum, _, _, _ = extract_packet_info(ack_packet)
        
        log_event(log_file, f"Packet sent; type=ACK; seqNum={seq_num}; length={length}; checksum={checksum:08x}")
        
        # sEnd using unreliable channel
        unreliable_channel.send_packet(socket, ack_packet, addr)
    except Exception as e:
        log_event(log_file, f"Error sending ACK: {e}")

def delayed_ack_handler(socket, seq_num, addr, log_file):
    """Handler for delayed ACK timeout"""
    global pending_ack
    
    if pending_ack is not None:
        send_ack(socket, seq_num, addr, log_file)
        pending_ack = None

def main():
    global expected_seq_num, received_data, pending_ack, delayed_ack_timer
    
    # Check command line arguments
    if len(sys.argv) != 4:
        print("Usage: ./MTPReceiver.py <receiver-port> <output-file> <receiver-log-file>")
        sys.exit(1)
    
    receiver_port = int(sys.argv[1])
    output_file = sys.argv[2]
    log_filename = sys.argv[3]
    
    # Open log file
    try:
        log_file = open(log_filename, 'w')
    except IOError as e:
        print(f"Error opening log file: {e}")
        sys.exit(1)
    
    # Create UDP socket
    try:
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver_socket.bind(('', receiver_port))
        log_event(log_file, f"Receiver socket bound to port {receiver_port}")
    except socket.error as e:
        log_event(log_file, f"Socket error: {e}")
        sys.exit(1)
    
    # Open output file
    try:
        with open(output_file, 'wb') as out_file:
            while True:
                try:
                    # Receive packet using unreliable channel
                    packet, sender_addr = unreliable_channel.recv_packet(receiver_socket)
                    
                    # Handle string corruption from unreliable_channel
                    try:
                        if isinstance(packet, bytes) and b"corrupted" in packet:
                            # Mark as corrupted without trying to parse
                            log_event(log_file, f"Packet received; status=CORRUPT (detected corruption string)")
                            if expected_seq_num > 0:
                                send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                            continue
                    except:
                        # If we can't check for corruption, packet is corrupt
                        log_event(log_file, f"Packet received; status=CORRUPT (invalid packet format)")
                        if expected_seq_num > 0:
                            send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                        continue
                    
                    # Extract packet info
                    result = extract_packet_info(packet)
                    
                    # Handling corrupt packets
                    if result is None or result[6]:
                        if result is not None:
                            packet_type, seq_num, length, checksum_in_packet, checksum_calculated, _, _ = result
                            log_event(log_file, f"Packet received; type=DATA; seqNum={seq_num}; length={length}; "
                                    f"checksum_in_packet={checksum_in_packet:08x}; "
                                    f"checksum_calculated={checksum_calculated:08x}; "
                                    f"status=CORRUPT")
                        else:
                            log_event(log_file, f"Packet received; status=CORRUPT")
                        
                        # Send duplicate ACK for the expected sequence number
                        if expected_seq_num > 0:
                            send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                        continue
                    
                    # Get packet fields
                    packet_type, seq_num, length, checksum_in_packet, checksum_calculated, data, _ = result
                    
                    # Handle DATA packets
                    if packet_type == DATA_PACKET:
                        # Check if in-order or out-of-order
                        if seq_num != expected_seq_num:
                            status = "OUT_OF_ORDER_PACKET"
                        else:
                            status = "NOT_CORRUPT"
                        
                        # Log received packet
                        log_event(log_file, f"Packet received; type=DATA; seqNum={seq_num}; length={length}; "
                                f"checksum_in_packet={checksum_in_packet:08x}; "
                                f"checksum_calculated={checksum_calculated:08x}; "
                                f"status={status}")
                        
                        # Handle in-order packet
                        if seq_num == expected_seq_num:
                            # Store the data
                            received_data[seq_num] = data
                            expected_seq_num += 1
                            
                            # Write consecutive packets to file
                            write_seq = seq_num
                            while write_seq in received_data:
                                try:
                                    out_file.write(received_data[write_seq])
                                    out_file.flush()  # Make sure to flush
                                except Exception as e:
                                    log_event(log_file, f"Error writing to file: {e}")
                                del received_data[write_seq]
                                write_seq += 1
                            
                            # Handle delayed ACK mechanism
                            if pending_ack is not None:
                                # We have a pending ACK, send cumulative ACK immediately
                                if delayed_ack_timer:
                                    delayed_ack_timer.cancel()
                                    delayed_ack_timer = None
                                
                                send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                                pending_ack = None
                            else:
                                # First packet, set up delayed ACK
                                pending_ack = expected_seq_num - 1
                                
                                # Start timer for delayed ACK
                                if delayed_ack_timer:
                                    delayed_ack_timer.cancel()
                                
                                # Use a lambda to capture the current context
                                delayed_ack_timer = threading.Timer(
                                    DELAYED_ACK_TIMEOUT, 
                                    lambda: delayed_ack_handler(receiver_socket, pending_ack, sender_addr, log_file)
                                )
                                delayed_ack_timer.daemon = True
                                delayed_ack_timer.start()
                        
                        # Handle out-of-order packet
                        elif seq_num > expected_seq_num:
                            # Store the data for future use
                            received_data[seq_num] = data
                            
                            # Send duplicate ACK immediately
                            send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                        
                        # Handle duplicate packet
                        else:  # seq_num < expected_seq_num
                            # Send ACK again
                            send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                
                except KeyboardInterrupt:
                    log_event(log_file, "Receiver interrupted by user")
                    break
                except Exception as e:
                    log_event(log_file, f"Error: {e}")
                    # Send previous ACK to make progress
                    if expected_seq_num > 0:
                        try:
                            send_ack(receiver_socket, expected_seq_num - 1, sender_addr, log_file)
                        except:
                            pass  # Ignore errors in error handler
                    continue
    
    except IOError as e:
        log_event(log_file, f"Error with output file: {e}")
    
    # Clean up
    if delayed_ack_timer:
        delayed_ack_timer.cancel()
    receiver_socket.close()
    log_file.close()

if __name__ == "__main__":
    main()