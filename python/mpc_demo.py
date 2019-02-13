"""
The script demonstrates the Unbound Tech blockchain-crypto-mpc library.
This example has two instances, a client and a server, which cooperate to execute crypto primitives via MPC.

A simple protocol is executed that starts with client sending command parameters to the server.
Messages are sent as is, preceded by length.

Usage:
    Server instance should have the '--server' flag.
    Client instance should have the hostname ('--host') of the server.
    Run with '--help' flag to see all parameter details.

Example 1: Generate a split EDDSA key
    user1@host1> python mpc_demo.py --out_file key_share.bin --server
    user2@host2> python mpc_demo.py --type EDDSA --command generate --out_file key_share.bin --host host1

Example 2: Sign with the split EDDSA key
    user1@host1> python mpc_demo.py --in_file key_share.bin --data_file data.dat --server
    user2@host2> python mpc_demo.py --type EDDSA --command sign --in_file key_share.bin --data_file data.dat --host host1
"""
import sys
import argparse
import socket
import struct
import datetime

import mpc_crypto

CLIENT = 1
SERVER = 2


def perform_step(obj, inMsgBuf):
    inMsg = mpc_crypto.messageFromBuf(inMsgBuf)

    outMsg, flags = mpc_crypto.step(obj.ctx, inMsg)
    mpc_crypto.freeMessage(inMsg)

    finished = flags & mpc_crypto.PROTOCOL_FINISHED_FLAG

    if flags & mpc_crypto.SHARE_CHANGED_FLAG:
        obj.setShare(mpc_crypto.getShare(obj.ctx))

    outMsgBuf = mpc_crypto.messageToBuf(outMsg)
    mpc_crypto.freeMessage(outMsg)
    return finished, outMsgBuf


def send_message(messageBuf):
    if not messageBuf:
        return
    length = len(messageBuf)
    clientsocket.send(struct.pack("!i", length))
    clientsocket.send(messageBuf)


def receive_message():
    rec = clientsocket.recv(4)
    length = struct.unpack("!i", rec)[0]
    chunks = []
    bytes_recd = 0
    while bytes_recd < length:
        chunk = clientsocket.recv(min(length - bytes_recd, 8192))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)


def exec_mpc_exchange(obj):
    finished = False
    messageBufIn = None
    messageBufOut = None
    while not finished:
        if peer == SERVER or messageBufOut:  # skip first receive by client
            messageBufIn = receive_message()

        finished, messageBufOut = perform_step(obj, messageBufIn)

        send_message(messageBufOut)


def run_eddsa_gen():
    print("Generating EDDSA key...")
    eddsaObj = mpc_crypto.Eddsa(peer)
    eddsaObj.initGenerate()
    exec_mpc_exchange(eddsaObj)
    print(" ok")
    return eddsaObj


def run_generate(cryptoType, size):
    print("Generating key...")
    if cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer)
        obj.initGenerate()
    elif cryptoType == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer)
        obj.initGenerate()
    elif cryptoType == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initGenerate(size)
    else:
        sys.exit("Generate not supported for " + cryptoType)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_sign(inShare, cryptoType):
    print(cryptoType + " signing...")
    if cryptoType == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer, inShare)
    elif cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer, inShare)
    else:
        sys.exit("Sign not supported for " + cryptoType)

    if not args.data_file:
        sys.exit("Input data missing")
    with open(args.data_file, "rb") as f:
        inData = f.read()
    with obj:
        obj.initSign(inData)
        exec_mpc_exchange(obj)
        sig = obj.getSignResult()
    print("ok")
    return sig


def run_import(inShare, cryptoType='generic'):
    print("Importing key...")
    if not inShare:
        sys.exit("Input share missing")
    if cryptoType == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initImport(inShare)
    else:
        sys.exit("Import not supported for " + cryptoType)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_derive(inShare, cryptoType='BIP32'):
    if cryptoType != 'BIP32':
        sys.exit("Derive not supported for " + args.type)
    srcObj = mpc_crypto.GenericSecret(peer, inShare)
    with srcObj:
        obj = mpc_crypto.Bip32(peer)
        with obj:
            obj.initDerive(srcObj, args.index, args.hardened)
            exec_mpc_exchange(obj)
            obj.getDeriveResult()
            return obj.exportShare()


def run_command(params):
    inStr = None
    if args.in_file:
        with open(args.in_file, "rb") as f:
            inStr = f.read()
    if params.command == 'generate':
        out = run_generate(params.type, params.size)
        outFileDefault = params.type + '_share'
    elif params.command == 'import':
        out = run_import(inStr, params.type)
        outFileDefault = params.type + '_share'
    elif params.command == 'derive':
        out = run_derive(inStr, params.type)
        outFileDefault = params.type + '_derived'
    elif params.command == 'sign':
        out = run_sign(inStr, params.type)
        outFileDefault = params.type + '_signature'
    outputFile = args.out_file if args.out_file else outFileDefault + \
        '_' + str(peer) + '.dat'
    return out, outputFile


def run_server():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    serversocket.bind((args.host, args.port))
    serversocket.listen(5)

    global clientsocket
    clientsocket, address = serversocket.accept()
    params = argparse.Namespace()
    while True:
        header = clientsocket.recv(3*4)
        if not header:
            break
        params.command = commands[struct.unpack("i", header[:4])[0]]
        params.type = types[struct.unpack("i", header[4:8])[0]]
        params.size = struct.unpack("i", header[8:])[0]
        print(params)
        out, outputFile = run_command(params)

    if params.command != 'sign':  # only client receives the signature
        with open(outputFile, "wb") as f:
            f.write(out)
    clientsocket.close()


def run_client():
    global clientsocket
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    clientsocket.connect((args.host, args.port))

    header = struct.pack("i", commands.index(args.command)) + \
        struct.pack("i", types.index(args.type)) + \
        struct.pack("i", args.size)
    startTime = datetime.datetime.now()
    for _ in range(args.repeat):
        clientsocket.send(header)
        out, outputFile = run_command(args)
    endTime = datetime.datetime.now()
    tookMs = (endTime - startTime).total_seconds() * 1000 / args.repeat
    tookStr = 'Took ' + str(tookMs) + ' ms'
    if args.repeat > 1:
        tookStr += ' on average'
    print(tookStr)
    with open(outputFile, "wb") as f:
        f.write(out)
    clientsocket.close()


commands = ['generate', 'import', 'sign', 'derive']
types = ['EDDSA', 'ECDSA', 'BIP32', 'generic']
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                 conflict_handler='resolve',
                                 description='''Simple tester script.
                                  Executes queries from the test directry and compares with expected results''')

parser.add_argument('-h', '--host', default='localhost', help='Host name')
parser.add_argument('-p', '--port', default=15435,
                    type=int, help='MPC Server port')
parser.add_argument('-s', '--server', action='store_true',
                    help='Run MPC server')
parser.add_argument('-o', '--out_file', help='Output file name')
parser.add_argument('-i', '--in_file', help='Input file name')
parser.add_argument('-d', '--data_file', help='Data file name')
parser.add_argument('-c', '--command', choices=commands, help='MPC Operation')
parser.add_argument('-t', '--type', choices=types, help='MPC Operation')
parser.add_argument('--hardened', action='store_true',
                    help='BIP32 derive parameter')
parser.add_argument('--index', type=int, default=0,
                    help='BIP32 derive parameter')
parser.add_argument('--size', type=int, default=256,
                    help='Size parameter')
parser.add_argument('--repeat', type=int, default=1,
                    help='Run the command N times to measure performance')


args = parser.parse_args()
if not args.server:
    if not args.command or not args.type:
        parser.error('Command and Type required for Client')
clientsocket = None
if args.server:
    peer = SERVER
    run_server()
else:
    peer = CLIENT
    run_client()
