# UDP-s-reliable-transport-protocol
The Mason Transport Protocol (MTP) is a custom, reliable transport-layer protocol developed to run on top of UDP, a connectionless protocol that by default provides no guarantees for packet delivery, ordering, or data integrity. MTP addresses these limitations by implementing a reliable file transfer mechanism, offering a simplified but functional alternative to TCP for educational and experimental purposes.

MTP follows the Go-Back-N (GBN) sliding window protocol to achieve reliable, in-order delivery of data. The sender maintains a configurable window size (e.g., 7 packets) and continuously transmits packets until the window is full. If an ACK (acknowledgment) for a packet is not received within a fixed timeout, the sender retransmits all unacknowledged packets starting from the earliest one. This ensures recovery from packet loss, corruption, or reordering.

Each MTP packet includes:
- A sequence number for tracking order and duplicates
- A CRC32 checksum to detect data corruption
- And appropriate flags for data and acknowledgment messages.

The receiver validates incoming packets using the checksum. If a packet is valid and in order, it is written to the output file and an ACK is sent. If a packet is out of order or corrupted, the receiver discards it and resends the last correct ACK, prompting the sender to retransmit the missing data.

Key features of MTP include:
- Custom packet structure with headers and payload separation,
- Retransmission mechanism based on a timeout and selective acknowledgment,
- Receiver-side buffering and file output with proper file reassembly,
- Connection management using simple state tracking for graceful start and termination,
- Performance handling for high-latency or lossy simulated networks.

The project includes two command-line tools: mtp_send for sending a file and mtp_recv for receiving it. Both tools communicate over UDP sockets but abstract away the complexity from the user by handling reliability internally via the MTP protocol.

MTP demonstrates a deep understanding of network protocol design and provides hands-on experience with concepts such as sliding window protocols, checksums, timeout-based retransmission, and data framing — all crucial in building reliable systems over unreliable channels.

how to run:

1. Start the receiver:
   python MTPReceiver.py <port> <output_file> <receiver_log>

   Example:
   python MTPReceiver.py 5000 output_file.txt receiver_log.txt

2. Then run the sender:
   python MTPSender.py <receiver_ip> <port> <window_size> <input_file> <sender_log>

   Example:
   python MTPSender.py localhost 5000 5 1MB.txt sender_log.txt

You can check if the file transferred correctly:
   python -c "import filecmp; print(filecmp.cmp('1MB.txt', 'output_file.txt'))"

Required libraries:
- socket (for UDP communication)
- sys (for command-line arguments)
- zlib (for CRC32 checksums)
- threading (for timers and concurrency)
- time (for timeouts)

no extra libraries need to be installed

Environment setup:
- Make sure Python 3 installed
- No extra setup is needed
- Keep all the files (MTPSender.py, MTPReceiver.py, and unreliable_channel.py) in the same folder
