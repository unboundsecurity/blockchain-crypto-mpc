import sys
import argparse
import socket
import struct
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


def run_generate():
    print("Generating key...")
    if args.type == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer)
        obj.initGenerate()
    elif args.type == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer)
        obj.initGenerate()
    elif args.type == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initGenerate(args.size)
    else:
        sys.exit("Generate not supported for " + args.type)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_sign(inShare):
    print(args.type + " signing...")
    if args.type == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer, inShare)
    elif args.type == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer, inShare)
    else:
        sys.exit("Sign not supported for " + args.type)

    if not args.data_file:
        sys.exit("Input data missing")
    with open(args.data_file, "rb") as f:
        inData = f.read()
    with obj:
        obj.initSign(inData, True)
        exec_mpc_exchange(obj)
        sig = obj.getSignResult()
    print("ok")
    return sig


def run_import(inShare):
    print("Importing key...")
    if not inShare:
        sys.exit("Input share missing")
    if args.type == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initImport(inShare)
    else:
        sys.exit("Import not supported for " + args.type)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_derive(inShare):
    if args.type != 'BIP32':
        sys.exit("Derive not supported for " + args.type)
    srcObj = mpc_crypto.GenericSecret(peer, inShare)
    with srcObj:
        obj = mpc_crypto.Bip32(peer)
        with obj:
            obj.initDerive(srcObj, args.index, args.hardened)
            exec_mpc_exchange(obj)
            obj.getDeriveResult()
            return obj.exportShare()


def run_command():
    inStr = None
    if args.in_file:
        with open(args.in_file, "rb") as f:
            inStr = f.read()
    if args.command == 'generate':
        out = run_generate()
        outFileDefault = args.type + '_share'
    elif args.command == 'import':
        out = run_import(inStr)
        outFileDefault = args.type + '_share'
    elif args.command == 'derive':
        out = run_derive(inStr)
        outFileDefault = args.type + '_derived'
    elif args.command == 'sign':
        out = run_sign(inStr)
        outFileDefault = args.type + '_signature'

    outputFile = args.out_file if args.out_file else outFileDefault + \
        '_' + str(peer) + '.dat'
    with open(outputFile, "wb") as f:
        f.write(out)


def run_server():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((args.host, args.port))
    serversocket.listen(5)

    global clientsocket
    clientsocket, address = serversocket.accept()
    run_command()
    clientsocket.close()


def run_client():
    global clientsocket
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((args.host, args.port))

    run_command()
    clientsocket.close()


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
parser.add_argument('-c', '--command', default='generate', choices=['generate', 'import', 'sign', 'derive'],
                    required=True, help='MPC Operation')
parser.add_argument('-t', '--type', default='eddsa', choices=['EDDSA', 'ECDSA', 'BIP32', 'generic'],
                    required=True, help='MPC Operation')
parser.add_argument('--hardened', action='store_true',
                    help='BIP32 derive parameter')
parser.add_argument('--index', type=int, default=0,
                    help='BIP32 derive parameter')
parser.add_argument('--size', type=int, default=256,
                    help='Size parameter')


args = parser.parse_args()
clientsocket = None

if args.server:
    peer = SERVER
    run_server()
else:
    peer = CLIENT
    run_client()
