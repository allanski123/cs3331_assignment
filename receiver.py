#!/usr/bin/env python3

import socket, sys, re, pickle, time

# globals for timer
currentTime = 0

dataReceived = 0
dataSegments = 0
bitErrors = 0
dupPackets = 0
dupAckPackets = 0

def checkSum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        if(i + 1 < len(msg)):
            a = msg[i]
            b = msg[i + 1]
            s = s + (a+(b << 8))
        elif(i + 1 == len(msg)):
            s += msg[i]
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def main():
    global dataReceived
    global dataSegments
    global bitErrors
    global dupPackets
    global dupAckPackets

    if(len(sys.argv) != 3):
        sys.exit("Usage: ./receiver receiver_port file_r.pdf")

    # Set the appropriate values provided from args
    recv_port = int(sys.argv[1])
    file_name = sys.argv[2]

    # initiate UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tup = ('127.0.0.1', recv_port)
    sock.bind(tup)
    startTimer()

    count = 0
    lastAck = 1
    buffer = []
    lookup = {}
    dataSizes = {}
    while True:
        data, address = sock.recvfrom(4096)
        list = pickle.loads(data)
        type = list[0]
        length = list[1]
        chkSum = list[2]
        seqNum = list[3]
        ackNum = list[4]
        msg = ""

        if(len(list) == 6):
            msg = list[5]

        if(chkSum != 0 and checkSum(msg) != chkSum):
            bitErrors += 1
            dataSegments += 1
            print("CheckSum was violated! Ignore corrupted packet!")
            logTime(list, "rcv/corr", "D")
            continue

        response = []
        if(type == "Syn"):
            logTime(list, "rcv", "S")
            response = createAck("Synack", 0, seqNum + 1)
            logTime(response, "snd", "SA")
        elif(type == "Ack"):
            logTime(list, "rcv", "A")
            continue
        elif(type == "Psh"):
            if(seqNum == lastAck):
                dataSegments += 1
                logTime(list, "rcv", "D")
                lookup.setdefault(seqNum, "")
                lookup[seqNum] = msg
                dataSizes.setdefault(seqNum, 0)
                dataSizes[seqNum] = length
                lastAck = seqNum + length
                response = createAck("Ack", ackNum, lastAck)
                file = open(file_name, 'ab')
                file.write(msg)
                count += 1
                logTime(response, "snd", "A")
            else:
                if(seqNum not in lookup):
                    dataSegments += 1
                    logTime(list, "rcv", "D")
                    buffer.append(seqNum)
                    lookup.setdefault(seqNum, "")
                    lookup[seqNum] = msg
                    dataSizes.setdefault(seqNum, 0)
                    dataSizes[seqNum] = length
                    # testing
                    response = createAck("Buf", ackNum, seqNum + length)
                    sock.sendto(pickle.dumps(response), address)
                    # remove maybe ^
                    response = createAck("DupAck", ackNum, lastAck)
                    dupAckPackets += 1
                    logTime(response, "snd/DA", "A")
                else:
                    dupPackets += 1
                    print("Ignoring: Psh packet " + str(seqNum))
                    continue
        elif(type == "Rxt"):
            cumAck = seqNum + length
            if(seqNum == lastAck):
                dataSegments += 1
                logTime(list, "rcv", "D")
                file = open(file_name, 'ab')
                file.write(msg)
                packetsAcked = 0
                for elem in sorted(buffer):
                    if(cumAck == elem):
                        file = open(file_name, 'ab')
                        file.write(lookup[cumAck])
                        cumAck += dataSizes[cumAck]
                        packetsAcked += 1
                lastAck = cumAck
                response = createAck("Ack", ackNum, lastAck)
                logTime(response, "snd", "A")
                print("Cumulative Ack: " + str(lastAck))
                for i in range(packetsAcked):
                    buffer.pop(0)
            else:
                dupPackets += 1
                print("Ignoring: RXT packet " + str(seqNum))
                continue

        elif(type == "Fin"):
            dataReceived = seqNum - 1
            logTime(list, "rcv", "F")
            response = createAck("Ack", ackNum, seqNum + 1)
            sock.sendto(pickle.dumps(response), address)
            logTime(response, "snd", "A")
            print("\n", response)

            response = createAck("Fin", ackNum, seqNum + 1)
            sock.sendto(pickle.dumps(response), address)
            logTime(response, "snd", "F")
            print(response)
            ack = sock.recvfrom(4096)[0]
            logTime(pickle.loads(ack), "rcv", "A")
            break;

        if(type != "Ack" and response):
            sock.sendto(pickle.dumps(response), address)
        # print the responses from server to client
        print(response)

    print("Closing Socket!")
    sock.close()
    logStats()

def startTimer():
    global currentTime
    currentTime = time.time()

    return currentTime

def logTime(packet, type, symbol):
    global currentTime
    packetTime = round(time.time() - currentTime, 2)
    file = open("Receiver_log.txt", 'a')

    seq = 0
    size = 0
    ack = 0

    if(len(packet) == 3):
        seq = str(packet[1])
        size = "0"
        ack = str(packet[2])
    else:
        seq = str(packet[3])
        size = str(packet[1])
        ack = str(packet[4])

    file.write('{:>10}\t\t{:>10}\t\t{:>10}\t\t{:>10}\t\t{:>10}\t\t{:>10}{}'.format(\
                type, packetTime, symbol, seq, size, ack, "\n"))

def logStats():
    res = "============================================================="
    res += "\nAmount of data received (bytes))                 " + str(dataReceived)
    res += "\nTotal Segments Received                          " + str(dataSegments + 4)
    res += "\nData segments received                           " + str(dataSegments)
    res += "\nData segments with Bit Errors                    " + str(bitErrors)
    res += "\nDuplicate data segments received                 " + str(dupPackets)
    res += "\nDuplicate ACKs sent                              " + str(dupAckPackets)
    res += "\n============================================================="

    file = open("Receiver_log.txt", 'a')
    file.write(res)

def createAck(type, seqNum, ackNum):
    packet = []
    packet.append(type)
    packet.append(seqNum)
    packet.append(ackNum)

    return packet

if __name__ == "__main__":
    main()
