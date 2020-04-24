#! /usr/bin/python3
#
# @(!--#) @(#) wotftp.py, version 011, 20-april-2020
#
# a TFTP server that only does write transfers
#
# the server assumes a super reliable connection
#

##############################################################################

#
# Help from:
# ---------
#
#    https://pymotw.com/2/socket/tcp.html
#    https://pymotw.com/2/socket/udp.html
#    http://www.tcpipguide.com/free/t_TrivialFileTransferProtocolTFTP.htm
#

#
# Packet format
# -------------
#
# Offset    Length   Notes
# ------    ------   -----
#
#   0-1     2        Operation code
#                    1 = Read Request
#                    2 = Write request
#                    3 = Data
#                    4 = Acknowledgment
#                    5 = Error
#                    6 = Option Acknowledgment
#

##############################################################################

#
# imports
#

import os
import sys
import argparse
import socket
import select
import time
import datetime

##############################################################################

#
# constants
#

MAX_PACKET_SIZE = 65536

DEFAULT_DIRECTORY       = '.'
DEFAULT_PORT            = 69
DEFAULT_BINDIP          = ''
DEFAULT_BLOCKSIZE       = 512
DEFAULT_SELECT_INTERVAL = 0.1
DEFAULT_IDLE_LIMIT      = 100
DEFAULT_VERBOSITY       = 1

##############################################################################

#
# globals
#

verbose = 1

##############################################################################

def logmsg(msg):
    global verbose
    
    if verbose == 0:
        return
        
    print(msg)
    
    return

##############################################################################

def showpacket(bytes):
    global verbose
    
    if verbose < 2:
        return
        
    bpr = 10              # bpr is Bytes Per Row
    
    numbytes = len(bytes)

    if numbytes == 0:
        print("<empty packet>")
    else:
        i = 0
        while i < numbytes:
            if (i % bpr) == 0:
                print("{:04d} :".format(i), sep='', end='')
            
            c = bytes[i]
            
            if (c < 32) or (c > 126):
                c = '?'
            else:
                c = chr(c)

            print(" {:02X} {} ".format(bytes[i], c), sep='', end='')

            if ((i + 1) % bpr) == 0:
                print()

            i = i + 1

    if (numbytes % bpr) != 0:
        print()

    return

##############################################################################

def unpackwriterequest(packet):
    errmsg = ''
    
    datafields = packet[2:].split(b'\x00')
    
    numdatafields = len(datafields)
    
    numdatafields -= 1
    
    if numdatafields < 2:
        errmsg = 'No data fields'
    elif (numdatafields % 2) != 0:
        errmsg = 'Number of data fields is not a multiple of 2'
    else:    
        options = {}
        
        filename = datafields[0].decode('utf-8')
        filemode = datafields[1].decode('utf-8')
        
        i = 2
        
        while i < numdatafields:
            optionname = datafields[i].decode('utf-8')
            i += 1

            optiontextvalue = datafields[i].decode('utf-8')
            i += 1
            
            if optionname == 'timeout':
                optionname = 'interval'
            
            try:
                optionvalue = int(optiontextvalue)
            except ValueError:
                errmsg = 'Bad option value - not an integer'
                break
            
            options[optionname] = optionvalue

    if errmsg == '':    
        return '', filename, filemode, options
    else:
        return errmsg, '', '', {}

##############################################################################

def validfilename(filename):
    validflag = True
    
    for c in filename:
        if c.isalpha():
            continue
        
        if c.isdigit():
            continue
        
        if c in '.-_':
            continue
            
        validflag = False
        break
    
    return validflag

##############################################################################

def relativepath(filename):
    while filename != '':
        if (filename[0] == '/') or (filename[0] == '\\'):
            filename = filename[1:]
        else:
            break
    
    return filename

##############################################################################

def localfilename(filename):
    bname = os.path.basename(filename)
    
    tstamp = '{:%Y-%m-%d-%H-%M-%S}'.format(datetime.datetime.now())
    
    return bname + '.' + tstamp

##############################################################################

def senderror(sock, clientip, clientport, errcode, errmsg):
    packet = bytearray(4 + len(errmsg) + 1)
    
    packet[0] = 0
    packet[1] = 5
    packet[2] = (errcode & 0xFF00) >> 8
    packet[3] = (errcode & 0x00FF) >> 0
    
    i = 4
    for c in errmsg:
        packet[i] = ord(c)
        i += 1
    
    packet[i] = 0

    print('Sending error code {} with message "{}"'.format(errcode, errmsg))
    showpacket(packet)

    sock.sendto(packet, (clientip, clientport))
    
    return

##############################################################################

def sendack(sock, clientip, clientport, blocknum):
    packet = bytearray(4)
    
    packet[0] = 0
    packet[1] = 4
    packet[2] = (blocknum & 0xFF00) >> 8
    packet[3] = (blocknum & 0x00FF) >> 0
    
    logmsg('Sending ACK to block number {}'.format(blocknum))
    showpacket(packet)
    
    sock.sendto(packet, (clientip, clientport))

    return

##############################################################################

def sendoptionack(sock, clientip, clientport, options):
    packet = bytearray(MAX_PACKET_SIZE)
    
    packet[0] = 0
    packet[1] = 6
    
    i = 2

    for optionname in options:
        optionvalue = options[optionname]
        optiontextvalue = '{}'.format(optionvalue)
        
        for c in optionname:
            packet[i] = ord(c)
            i += 1
        packet[i] = 0
        i += 1
        
        for c in optiontextvalue:
            packet[i] = ord(c)
            i += 1
        packet[i] = 0
        i += 1
        
    logmsg('Sending option ACK')
    showpacket(packet[0:i])
    
    sock.sendto(packet[0:i], (clientip, clientport))

    return

##############################################################################

def mainpacketloop(sock, remoteip, timestampflag, ipstampflag):
    global verbose
    
    state = 'idle'
    
    d = datetime.datetime.now()
    logmsg('Server started at {:02d}:{:02d}:{:02d}'.format(d.hour, d.minute, d.second))
    
    while True:
        idlecounter = 0

        while True:
            ready, dummy1, dummy2 = select.select([sock], [], [], DEFAULT_SELECT_INTERVAL)
            
            if len(ready) > 0:
                break
            
            idlecounter += 1
            
            if idlecounter > DEFAULT_IDLE_LIMIT:
                d = datetime.datetime.now()
                logmsg('Idle at {:02d}:{:02d}:{:02d}'.format(d.hour, d.minute, d.second))             
                idlecounter = 0
                if state != 'idle':
                    logmsg('Forcing state to idle')
                    try:
                        fhandle.close()
                    except IOError:
                        pass
                    state = 'idle'
                    
        try:
            packet, address = sock.recvfrom(MAX_PACKET_SIZE)
        except ConnectionResetError:
            logmsg('Connection reset error')
            continue
        
        clientip = address[0]
        clientport = address[1]
        
        if remoteip != '':
            if clientip != remoteip:
                logmsg('Packet from unknown IP address {} - only allowing IP {}'.format(clientip, remoteip))
                continue
        
        if len(packet) == 0:
            logmsg('Empty packet received - ignoring')
            continue
            
        if len(packet) < 4:
            logmsg('Packet received too short - ignoring')
            continue
        
        opcode = (packet[0] * 256) + packet[1]
        
        if (opcode < 1) or (opcode > 6):
            logmsg('Invalid opcode {}'.format(opcode))
            continue

        ##############
        # read request
        ##############
        if opcode == 1:
            logmsg('Read request')
            senderror(sock, clientip, clientport, 2, 'read request not supported - write requests only')
            continue
            
        ###############
        # write request
        ###############        
        if opcode == 2:
            logmsg('Write request')
            showpacket(packet)
            if state != 'idle':
                senderror(sock, clientip, clientport, 0, 'server is busy - try again later')
                continue
            errmsg, filename, filemode, options = unpackwriterequest(packet)
            if errmsg != '':
                senderror(sock, clientip, clientport, 8, 'bad option in write request')
                continue
            
            logmsg('Filename: {}'.format(filename))
            logmsg('Transfer mode: {}'.format(filemode))
            
            if not validfilename(filename):
                senderror(sock, clientip, clientport, 0, 'invalid filename')
                continue
            
            if timestampflag:
                d = datetime.datetime.now()
                filename = '{}-{:04d}-{:02d}-{:02d}-{:02d}-{:02d}-{:02d}-{:03d}'.format(filename, d.year, d.month, d.day, d.hour, d.minute, d.second, (d.microsecond) // 1000)
                time.sleep(0.002)
            if ipstampflag:
                filename = '{}-{}'.format(clientip, filename)
            try:
                fhandle = open(filename, 'wb')
            except IOError:
                senderror(sock, clientip, clientport, 2, 'cannot open file for writing on server')
                continue
            state = 'busy'
            if 'blksize' in options:
                blocksize = options['blksize']
            else:
                blocksize = DEFAULT_BLOCKSIZE
            logmsg('Block size: {}'.format(blocksize))
            for optionname in options:
                optionvalue = options[optionname]
                logmsg('Option {}={}'.format(optionname, optionvalue))
            if len(options) == 0:
                sendack(sock, clientip, clientport, 0)
            else:
                sendoptionack(sock, clientip, clientport, options)
            nextblock = 1
            continue
        
        ######
        # data
        ######
        if opcode == 3:
            blocknum = (packet[2] * 256) + packet[3]
            logmsg('Incoming data packet with block number {}'.format(blocknum))
            showpacket(packet)
            if state != 'busy':
                senderror(sock, clientip, clientport, 0, 'data block received but server not expecting any')
                continue
            if blocknum != nextblock:
                logmsg('Data block mismatch - got {}, expected {} - ignoring'.format(blocknum, nextblock))
                continue
            sendack(sock, clientip, clientport, blocknum)
            lendata = len(packet) - 4
            if lendata > 0:
                logmsg('Writing {} bytes of data from block number {}'.format(lendata, blocknum))
                fhandle.write(packet[4:])
                nextblock += 1
            if lendata < blocksize:
                logmsg('Closing file')
                fhandle.close()
                state = 'idle'
            continue
            
        ######
        # ack
        ######
        if opcode == 4:
            logmsg('Incoming ACK')
            showpacket(packet)
            senderror(sock, clientip, clientport, 0, 'only servers should send ACK packets')
            continue        

        #######
        # error
        #######
        if opcode == 5:
            logmsg('Error message')
            showpacket(packet)
            if state == 'busy':
                try:
                    fhandle.close()
                except IOError:
                    pass
                state = 'idle'
            continue        

        ############
        # option ack
        ############
        if opcode == 6:
            logmsg('Incoming option ACK')
            showpacket(packet)
            senderror(sock, clientip, clientport, 0, 'only servers should send option ACK packets')
            continue        

        senderror(sock, clientip, clientport, 4, 'unsupported opcode {}'.format(opcode))
        
##############################################################################

#
# Main code
#

def main():
    global progname
    global verbose
    
    parser = argparse.ArgumentParser()

    parser.add_argument('--dir',       help='initial directory to change to (default is current directory)',             default=DEFAULT_DIRECTORY)
    parser.add_argument('--port',      help='TCP/IP port number to bind to (default is {})'.format(DEFAULT_PORT),        default=DEFAULT_PORT)
    parser.add_argument('--bind',      help='ip address to bind to (default is bind to all)',                            default=DEFAULT_BINDIP)
    parser.add_argument('--remoteip',  help='restrict access to just this remote ip address',                            default='')
    parser.add_argument('--timestamp', help='add time stamp to file name',                                               action='store_true')
    parser.add_argument('--ipstamp',   help='add IP address to file name',                                               action='store_true')
    parser.add_argument('--verbose',   help='verbosity level 0, 1 or 2 (default is {})'.format(DEFAULT_VERBOSITY),       default=DEFAULT_VERBOSITY)

    args = parser.parse_args()
    
    dir = args.dir
    try:
        port = int(args.port)
    except ValueError:
        port = DEFAULT_PORT
    bindip = args.bind
    remoteip = args.remoteip
    timestampflag = args.timestamp
    ipstampflag = args.ipstamp
    try:
        verbose = int(args.verbose)
    except ValueError:
        verbose = DEFAULT_VERBOSITY

    try:
        os.chdir(dir)
    except OSError:
        print("{}: unable to change to initial directory \"{}\"".format(progname, dir), file=sys.stderr)
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((bindip, port))

    mainpacketloop(sock, remoteip, timestampflag, ipstampflag)
    
    return 0
        
##########################################################################

progname = os.path.basename(sys.argv[0])

sys.exit(main())

# end of file
