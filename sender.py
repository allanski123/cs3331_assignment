#!/usr/bin/env python3

import socket, sys, time, pickle, random, array, datetime

"""
Milestones
- Implement stop & wait protocol (rdt 3.0)
- Implement packet drop functionality -> PLD
- Implement other errors (e.g. corrupted, out of order)
- Implement sending packets in windows
- Run tests
"""

# Global Variables for log file information
fileSize = 0
transmitted = 0
dropped = 0
corrupted = 0
reOrdered = 0
duplicated = 0
delayed = 0
timeouts = 0
fastRetrans = 0
totalDupAcks = 0

# Globals for other things
onHold = False
orderCount = 0
heldPacket = None
delayedPackets = []

# globals for timing
currentTime = 0
estimatedRTT = 0.5
devRTT = 0.25
timeout = 1
sampleTimer = 0
sampleSeq = 0
timerOn = False
gamma = 0

timeoutTimer = 0
timeoutSeq = 0

def main():
    if(len(sys.argv) != 15):
        msg = "Usage: ./sender receiver_host_ip receiver_port "
        msg += "file.pdf MWS MSS gamma pDrop pDuplicate pCorrupt "
        msg += "pOrder maxOrder pDelay maxDelay seed"
        sys.exit(msg)

    global gamma
    global currentTime

    # Set the appropriate values provided from args
    recv_ip = sys.argv[1]
    recv_port = int(sys.argv[2])
    file_name = sys.argv[3]
    MWS = int(sys.argv[4])
    MSS = int(sys.argv[5])
    gamma = float(sys.argv[6])
    pDrop = float(sys.argv[7])
    pDuplicate = float(sys.argv[8])
    pCorrupt = float(sys.argv[9])
    pOrder = float(sys.argv[10])
    maxOrder = int(sys.argv[11])
    pDelay = float(sys.argv[12])
    maxDelay = float(sys.argv[13])
    seed = int(sys.argv[14])

    # set seed for random number generator
    random.seed(seed)
    # initiate UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    startTimer()
    handshake(sock, recv_ip, recv_port)
    res = transmitFile(sock, file_name, recv_ip, recv_port, MWS, MSS, \
        pDrop, pDuplicate, pCorrupt, pOrder, pDelay, maxOrder, maxDelay)
    teardown(sock, recv_ip, recv_port, res[0], res[1])
    logStats()

    print(time.time() - currentTime)

def startTimer():
    global currentTime
    currentTime = time.time()

    return currentTime

def newTimeout(sample):
    global estimatedRTT
    global devRTT
    global timeout
    global gamma

    alpha = 0.125
    beta = 0.25

    estimatedRTT = (1 - alpha) * estimatedRTT + (alpha * sample)
    devRTT = (1 - beta) * devRTT + (beta * abs(sample - estimatedRTT))
    timeout = estimatedRTT + (gamma * devRTT)

    if(timeout > 60):
        timeout = 60
    if(timeout < 0.20):
        timeout = 0.20

def logTime(packet, type, symbol):
    global currentTime
    packetTime = round(time.time() - currentTime, 2)
    file = open("Sender_log.txt", 'a')

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

def handshake(sock, host, port):
    list = newPacket("Syn", 0, 0, 0, 0)
    sock.sendto(pickle.dumps(list), (host, port))
    logTime(list, "snd", "S")
    response = sock.recvfrom(4096)[0]
    logTime(pickle.loads(response), "rcv", "SA")

    list = newPacket("Ack", 0, 0, 1, 1)
    sock.sendto(pickle.dumps(list), (host, port))
    logTime(list, "snd", "A")

def teardown(sock, host, port, seqNum, ackNum):
    packet = newPacket("Fin", 0, 0, seqNum, ackNum)
    sock.sendto(pickle.dumps(packet), (host, port))
    logTime(packet, "snd", "F")
    response = sock.recvfrom(4096)[0]
    response = pickle.loads(response)
    logTime(response, "rcv", "A")
    print(packet)

    response = sock.recvfrom(4096)[0]
    response = pickle.loads(response)
    logTime(response, "rcv", "F")
    seq = getLastAck(response)
    ack = getLastSeq(response)
    packet = newPacket("Ack", 0, 0, seq, ack + 1)
    sock.sendto(pickle.dumps(packet), (host, port))
    logTime(packet, "snd", "A")
    print(packet)

    print("Closing Socket!")
    sock.close()

def newPacket(type, length, checkSum, seqNum, ackNum, msg=None):
    packet = []
    packet.append(type)
    packet.append(length)
    packet.append(checkSum)
    packet.append(seqNum)
    packet.append(ackNum)

    if(msg is not None):
        packet.append(msg)

    return packet

# http://www.bitforestinfo.com/2018/01/python-codes-to-calculate-ipv4-checksum.html
def checkSum(msg):
    s = 0
    lower = 0
    upper = len(msg)
    for i in range(lower, upper, 2):
        if(i + 1 < upper):
            a = msg[i]
            b = msg[i + 1]
            s += (a+(b << 8))
        elif(i + 1 == upper):
            s += msg[i]
    s += (s >> 16)
    s = ~s & 0xffff

    return s

def crptData(sum):
    binary = bin(sum)
    firstBit = binary[2]

    if(firstBit == '0'):
        firstBit = '1'
    else:
        firstBit = '0'

    return int(binary[:2] + firstBit + binary[3:], 2)

def pld(sock, host, port, pDrop, pDuplicate, pCorrupt, pOrder, pDelay, \
        maxOrder, maxDelay, packet, type):

    # log file globals
    global corrupted
    global transmitted

    # other globals
    global onHold
    global orderCount
    global heldPacket

    global delayedPackets
    global reOrdered
    global duplicated
    global delayed

    global sampleTimer
    global sampleSeq
    global timerOn

    dropRate = random.random()
    dupRate = random.random()
    crptRate = random.random()
    orderRate = random.random()
    delayRate = random.random()

    toRemove = []
    # check if delayed packets can be sent
    for curr in delayedPackets:
        timeNow = time.time()
        pack = curr[0]
        if((timeNow - curr[1]) * 1000 >= curr[2]):
            # maybe delete this
            if(not timerOn and pack[0] != "Rxt"):
                sampleTimer = time.time()
                sampleSeq = pack[3] + pack[1]
                timerOn = True

            toRemove.append(curr)
            pack[0] = "Rxt"
            print("Packet: dlay | SeqNum: " + str(pack[3]), \
                "| AckNum: " + str(pack[4]) + " | Type: " + type)
            sock.sendto(pickle.dumps(pack), (host, port))
            logTime(pack, "snd/dely", "D")
            orderCount += 1

    for i in toRemove:
        if(i in delayedPackets):
            delayedPackets.remove(i)

    if(dropRate < pDrop):
        print("Packet: drop | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)
        logTime(packet, "drop", "D")
    elif(dupRate < pDuplicate):
        print("Packet: dupl | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)
        print("Packet: dupl | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)
        sock.sendto(pickle.dumps(packet), (host, port))
        logTime(packet, "snd", "D")
        sock.sendto(pickle.dumps(packet), (host, port))
        logTime(packet, "snd/dup", "D")

        # maybe delete this
        if(not timerOn and packet[0] != "Rxt"):
            sampleTimer = time.time()
            sampleSeq = packet[3] + packet[1]
            timerOn = True

        # transmitted counted twice?
        transmitted += 1
        orderCount += 1
        duplicated += 1
    elif(crptRate < pCorrupt):
        print("Packet: crpt | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)
        crpted = crptData(packet[2])
        packet[2] = crpted
        sock.sendto(pickle.dumps(packet), (host, port))
        logTime(packet, "snd/corr", "D")

        corrupted += 1
        orderCount += 1
    elif(orderRate < pOrder):
        if(onHold):
            orderCount += 1
            sock.sendto(pickle.dumps(packet), (host, port))
            logTime(packet, "snd", "D")
            print("Packet: CBHE | SeqNum: " + str(packet[3]), \
                "| AckNum: " + str(packet[4]) + " | Type: " + type)
            # maybe delete this
            if(not timerOn and packet[0] != "Rxt"):
                sampleTimer = time.time()
                sampleSeq = packet[3] + packet[1]
                timerOn = True
        else:
            onHold = True
            heldPacket = packet
            orderCount = 0
            print("We had to hold back packet | SeqNum: " + str(packet[3]), \
                "| AckNum: " + str(packet[4]) + " | Type: " + type)

            reOrdered += 1
    elif(delayRate < pDelay):
        sendTime = time.time()
        delay = random.randint(0, maxDelay)
        delayInfo = [packet, sendTime, delay]
        delayedPackets.append(delayInfo)
        print("We had to delay packet | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)

        delayed += 1
    else:
        sock.sendto(pickle.dumps(packet), (host, port))
        if(type == "Rxt"):
            logTime(packet, "snd/RXT", "D")
        else:
            logTime(packet, "snd", "D")
            print(sampleSeq)
            if(not timerOn):
                sampleTimer = time.time()
                sampleSeq = packet[3] + packet[1]
                timerOn = True

        print("Packet: Sent | SeqNum: " + str(packet[3]), \
            "| AckNum: " + str(packet[4]) + " | Type: " + type)
        orderCount += 1

    if(orderCount == maxOrder and (heldPacket is not None)):
        # maybe delete this
        if(not timerOn and heldPacket[0] != "Rxt"):
            sampleTimer = time.time()
            sampleSeq = heldPacket[3] + heldPacket[1]
            timerOn = True

        heldPacket[0] = "Rxt"
        print("Packet: held | SeqNum: " + str(heldPacket[3]), \
            "| AckNum: " + str(heldPacket[4]) + " | Type: " + type)
        sock.sendto(pickle.dumps(heldPacket), (host, port))
        logTime(heldPacket, "snd/rord", "D")
        onHold = False
        # recently chaanged this
        heldPacket = None

def transmitFile(sock, file, host, port, MWS, MSS, pDrop, pDuplicate, \
        pCorrupt, pOrder, pDelay, maxOrder, maxDelay):
    # Variables for transmitting file
    file = open(file, 'rb')
    chunk = file.read(MSS)
    count = 0
    seqNum = 1
    ackNum = 1
    window = 0
    prevAck = 1
    ackDups = 1
    windowSize = MWS/MSS
    list = []
    lookup = {}

    # Variables for log file
    global fileSize
    global transmitted
    global dropped
    global timeouts
    global fastRetrans
    global totalDupAcks

    global timeout
    global sampleTimer
    global sampleSeq
    global timerOn


    global timeoutTimer
    global timeoutSeq

    while(chunk or list):
        while(window < windowSize):
            list.append(seqNum)
            if(not chunk):
                break;
            lookup.setdefault(seqNum, "")
            lookup[seqNum] = chunk
            chkSum = checkSum(chunk)
            fileSize += len(chunk)
            transmitted += 1
            print("THE TIMER IS: " + str(timeout))
            sock.settimeout(timeout)
            packet = newPacket("Psh", len(chunk), chkSum, seqNum, ackNum, chunk)
            pld(sock, host, port, pDrop, pDuplicate, pCorrupt, pOrder, pDelay, \
                    maxOrder, maxDelay, packet, "Psh")
            # start the timer for timeout
            if(timeoutTimer == 0):
                timeoutTimer = time.time()
                timeoutSeq = seqNum

            seqNum += len(chunk)
            window += 1
            count += 1
            chunk = file.read(MSS)
        try:
            tmp = []
            # if timer on packet > timeout value - trigger except to retransmit
            if(time.time() - timeoutTimer > timeout and timeoutTimer == -1):
                timeoutTimer = time.time()
                tmp[1] = 0

            response = sock.recvfrom(4096)[0]
            response = pickle.loads(response)

            if(getType(response) == "DupAck"):
                ackDups += 1
                totalDupAcks += 1
                logTime(response, "rcv/DA", "A")
            elif(getType(response) == "Buf" and timerOn):
                if(getLastAck(response) == sampleSeq):
                    sampleRTT = time.time() - sampleTimer
                    newTimeout(sampleRTT)
                    timerOn = False
                    sampleTimer = 0
            elif(getType(response) != "DupAck" and getType(response) != "Buf"):
                if(getLastAck(response) == sampleSeq and timerOn):
                    sampleRTT = time.time() - sampleTimer
                    newTimeout(sampleRTT)
                    timerOn = False
                    sampleTimer = 0

                tempList = []
                for i in list:
                    if(i > getLastAck(response)):
                        tempList.append(i)
                list = tempList

                if(ackDups > 1):
                    ackDups = 1
                tmp = (getLastAck(response) - prevAck) / MSS
                prevAck = getLastAck(response)
                # update window
                windowSize += tmp
                timeoutTimer = time.time()
                timeoutSeq = prevAck

                print("Window slid " + str(tmp) + " packets!")
                logTime(response, "rcv", "A")

            if(ackDups == 4):
                oldChunk = lookup[prevAck]
                chkSum = checkSum(oldChunk)
                packet = newPacket("Rxt", len(oldChunk), chkSum, prevAck, ackNum, oldChunk)
                pld(sock, host, port, pDrop, pDuplicate, pCorrupt, pOrder, \
                        pDelay, maxOrder, maxDelay, packet, "Rxt")
                print("Retrasnmitted packet: " + str(prevAck))
                transmitted += 1
                dropped += 1
                fastRetrans += 1
        except:
            print("TIMEOUT")
            oldChunk = lookup[prevAck]
            chkSum = checkSum(oldChunk)
            packet = newPacket("Rxt", len(oldChunk), chkSum, prevAck, 1, oldChunk)
            pld(sock, host, port, pDrop, pDuplicate, pCorrupt, pOrder, \
                    pDelay, maxOrder, maxDelay, packet, "Rxt")
            print("Resent packet: " + str(prevAck))
            transmitted += 1
            dropped += 1
            timeouts += 1

            if(packet[3] < seqNum):
                timerOn = False

    return [seqNum, ackNum]

def logStats():
    res = "============================================================="
    res += "\nSize of the file (in Bytes)                      " + str(fileSize)
    res += "\nSegments transmitted (including drop & RXT)      " + str(transmitted + 4)
    res += "\nNumber of Segments handled by PLD                " + str(transmitted)
    res += "\nNumber of Segments dropped                       " + str(dropped)
    res += "\nNumber of Segments Corrupted                     " + str(corrupted)
    res += "\nNumber of Segments Re-ordered                    " + str(reOrdered)
    res += "\nNumber of Segments Duplicated                    " + str(duplicated)
    res += "\nNumber of Segments Delayed                       " + str(delayed)
    res += "\nNumber of Retransmissions due to TIMEOUT         " + str(timeouts)
    res += "\nNumber of FAST RETRANSMISION                     " + str(fastRetrans)
    res += "\nNumber of DUP ACKS RECEIVED                      " + str(totalDupAcks)
    res += "\n============================================================="

    file = open("Sender_log.txt", 'a')
    file.write(res)


def getType(packet):
    return packet[0]

def getLastSeq(packet):
    return packet[1]

def getLastAck(packet):
    return packet[2]

if __name__ == "__main__":
    main()
