from ctypes import *

dll_name = "mpc_crypto"
libmpc = CDLL(dll_name)

KEY_TYPE_EDDSA = 2
KEY_TYPE_ECDSA = 3
KEY_TYPE_GENERIC_SECRET = 4  # used for the seed

MPC_ERR_BADARG = 0xff010002  # bad argument
MPC_ERR_FORMAT = 0xff010003  # invalid format
MPC_ERR_TOO_SMALL = 0xff010008  # buffer too small
MPC_ERR_CRYPTO = 0xff040001  # crypto error, process is being tampered


class MPCException(Exception):

    def __init__(self, error_code):
        # Exception.__init__()
        self.error_code = error_code


def test_rv(rv):
    if rv != 0:
        raise MPCException(rv)


PROTOCOL_FINISHED_FLAG = 1
SHARE_CHANGED_FLAG = 2

libmpc.MPCCrypto_initGenerateGenericSecret.argtypes = [
    c_int, c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initGenerateGenericSecret.restype = c_uint
libmpc.MPCCrypto_initImportGenericSecret.argtypes = [
    c_int, c_char_p, c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initImportGenericSecret.restype = c_uint


def initGenerateGenericSecret(peer, bits):
    ctx = c_void_p()
    test_rv(libmpc.MPCCrypto_initGenerateGenericSecret(
        c_int(peer), c_int(bits), byref(ctx)))
    return ctx


def initImportGenericSecret(peer, data):
    ctx = c_void_p()
    test_rv(libmpc.MPCCrypto_initImportGenericSecret(
        c_int(peer), c_char_p(data), c_int(len(data)), byref(ctx)))
    return ctx


#  Memory management
libmpc.MPCCrypto_freeContext.argtypes = [c_void_p]
libmpc.MPCCrypto_freeContext.restype = None
libmpc.MPCCrypto_freeShare.argtypes = [c_void_p]
libmpc.MPCCrypto_freeShare.restype = None
libmpc.MPCCrypto_freeMessage.argtypes = [c_void_p]
libmpc.MPCCrypto_freeMessage.restype = None


def freeContext(ptr):
    if ptr:
        libmpc.MPCCrypto_freeContext(ptr)


def freeShare(ptr):
    if ptr:
        libmpc.MPCCrypto_freeShare(ptr)


def freeMessage(ptr):
    if ptr:
        libmpc.MPCCrypto_freeMessage(ptr)


#  Serialization
libmpc.MPCCrypto_shareToBuf.argtypes = [
    c_void_p, POINTER(c_char), POINTER(c_int)]
libmpc.MPCCrypto_shareToBuf.restype = c_uint
libmpc.MPCCrypto_contextToBuf.argtypes = [
    c_void_p, POINTER(c_char), POINTER(c_int)]
libmpc.MPCCrypto_contextToBuf.restype = c_uint
libmpc.MPCCrypto_messageToBuf.argtypes = [
    c_void_p, POINTER(c_char), POINTER(c_int)]
libmpc.MPCCrypto_messageToBuf.restype = c_uint


def shareToBuf(share):
    if not share:
        return None
    out_size = c_int()
    test_rv(libmpc.MPCCrypto_shareToBuf(share, None, byref(out_size)))
    buf = create_string_buffer(out_size.value)
    test_rv(libmpc.MPCCrypto_shareToBuf(share, buf, byref(out_size)))
    return buf.raw


def contextToBuf(ctx):
    if not ctx:
        return None
    out_size = c_int()
    test_rv(libmpc.MPCCrypto_contextToBuf(ctx, None, byref(out_size)))
    buf = create_string_buffer(out_size.value)
    test_rv(libmpc.MPCCrypto_contextToBuf(ctx, buf, byref(out_size)))
    return buf.raw


def messageToBuf(msg):
    if not msg:
        return None
    out_size = c_int()
    test_rv(libmpc.MPCCrypto_messageToBuf(msg, None, byref(out_size)))
    buf = create_string_buffer(out_size.value)
    test_rv(libmpc.MPCCrypto_messageToBuf(msg, buf, byref(out_size)))
    return buf.raw


#  Deserialization
libmpc.MPCCrypto_shareFromBuf.argtypes = [
    POINTER(c_char), c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_shareFromBuf.restype = c_uint
libmpc.MPCCrypto_contextFromBuf.argtypes = [
    POINTER(c_char), c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_contextFromBuf.restype = c_uint
libmpc.MPCCrypto_messageFromBuf.argtypes = [
    POINTER(c_char), c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_messageFromBuf.restype = c_uint


def shareFromBuf(buf):
    if not buf:
        return None
    share = c_void_p()
    test_rv(libmpc.MPCCrypto_shareFromBuf(
        c_char_p(buf), c_int(len(buf)), byref(share)))
    return share


def contextFromBuf(buf):
    if not buf:
        return None
    ctx = c_void_p()
    test_rv(libmpc.MPCCrypto_contextFromBuf(
        c_char_p(buf), c_int(len(buf)), byref(ctx)))
    return ctx


def messageFromBuf(buf):
    if not buf:
        return None
    msg = c_void_p()
    test_rv(libmpc.MPCCrypto_messageFromBuf(
        c_char_p(buf), c_int(len(buf)), byref(msg)))
    return msg


class share_info_t(Structure):
    _fields_ = [("uid", c_uint64),
                ("type", c_uint)]


class context_info_t(Structure):
    _fields_ = [("uid", c_uint64),
                ("share_uid", c_uint64),
                ("peer", c_int)
                ]


class message_info_t(Structure):
    _fields_ = [("context_uid", c_uint64),
                ("share_uid", c_uint64),
                ("src_peer", c_int),
                ("dst_peer", c_int)
                ]



#  Information
# libmpc.MPCCrypto_shareInfo(MPCCryptoShare * share,     mpc_crypto_share_info_t * info)
# libmpc.MPCCrypto_contextInfo(MPCCryptoContext * context, mpc_crypto_context_info_t * info)
# libmpc.MPCCrypto_messageInfo(MPCCryptoMessage * message, mpc_crypto_message_info_t * info)
libmpc.MPCCrypto_shareInfo.argtypes = [c_void_p, POINTER(share_info_t)]
libmpc.MPCCrypto_contextInfo.argtypes = [c_void_p, POINTER(context_info_t)]
libmpc.MPCCrypto_messageInfo.argtypes = [c_void_p, POINTER(message_info_t)]
libmpc.MPCCrypto_shareInfo.restype = c_uint
libmpc.MPCCrypto_contextInfo.restype = c_uint
libmpc.MPCCrypto_messageInfo.restype = c_uint


def shareInfo(share):
    info = share_info_t()
    test_rv(libmpc.MPCCrypto_shareInfo(share, info))
    return info


def contextInfo(ctx):
    info = context_info_t()
    test_rv(libmpc.MPCCrypto_contextInfo(ctx, info))
    return info


def messageInfo(msg):
    info = context_info_t()
    test_rv(libmpc.MPCCrypto_messageInfo(msg, info))
    return info


libmpc.MPCCrypto_step.argtypes = [c_void_p, c_void_p,
                                  POINTER(c_void_p), POINTER(c_uint)]
libmpc.MPCCrypto_step.restype = c_uint


def step(ctx, in_msg):
    out_msg = c_void_p()
    out_flags = c_uint()
    test_rv(libmpc.MPCCrypto_step(ctx, in_msg, byref(out_msg), byref(out_flags)))
    return out_msg, out_flags.value


libmpc.MPCCrypto_getShare.argtypes = [c_void_p, POINTER(c_void_p)]
libmpc.MPCCrypto_getShare.restype = c_uint


def getShare(ctx):
    share = c_void_p()
    test_rv(libmpc.MPCCrypto_getShare(ctx, byref(share)))
    return share


libmpc.MPCCrypto_initRefreshKey.argtypes = [c_int, c_void_p, POINTER(c_void_p)]
libmpc.MPCCrypto_initRefreshKey.restype = c_uint


def initRefreshKey(peer, share):
    ctx = c_void_p()
    test_rv(libmpc.MPCCrypto_initRefreshKey(c_int(peer), share, byref(ctx)))
    return ctx


#  EdDSA specific functions
libmpc.MPCCrypto_initGenerateEddsaKey.argtypes = [c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initGenerateEddsaKey.restype = c_uint
libmpc.MPCCrypto_initEddsaSign.argtypes = [
    c_int, c_void_p, c_char_p, c_int, c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initEddsaSign.restype = c_uint
libmpc.MPCCrypto_getResultEddsaSign.argtypes = [c_void_p, c_char_p]
libmpc.MPCCrypto_getResultEddsaSign.restype = c_uint
libmpc.MPCCrypto_verifyEddsa.argtypes = [c_char_p, c_char_p, c_int, c_char_p]
libmpc.MPCCrypto_verifyEddsa.restype = c_uint
libmpc.MPCCrypto_getEddsaPublic.argtypes = [c_void_p, c_char_p]
libmpc.MPCCrypto_getEddsaPublic.restype = c_uint


def initGenerateEddsaKey(peer):
    ptr = c_void_p()
    test_rv(libmpc.MPCCrypto_initGenerateEddsaKey(c_int(peer), byref(ptr)))
    return ptr


def initEddsaSign(peer, share, buf, refresh):
    ctx = c_void_p()
    iRefresh = 1 if refresh else 0
    libmpc.MPCCrypto_initEddsaSign(
        c_int(peer), share, c_char_p(buf), c_int(len(buf)), c_int(iRefresh), byref(ctx))
    return ctx


def getEddsaSignResult(ctx):
    sig = create_string_buffer(64)
    test_rv(libmpc.MPCCrypto_getResultEddsaSign(ctx, sig))
    return sig.raw


def verifyEddsa(pub_key, test, sig):
    test_rv(libmpc.MPCCrypto_verifyEddsa(c_char_p(pub_key),
                                         c_char_p(test), c_int(len(test)), c_char_p(sig)))


def getEddsaPublic(key):
    pub_key = create_string_buffer(32)
    test_rv(libmpc.MPCCrypto_getEddsaPublic(key, pub_key))
    return pub_key.raw


#  ECDSA specific functions
libmpc.MPCCrypto_initGenerateEcdsaKey.argtypes = [c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initGenerateEcdsaKey.restype = c_uint
libmpc.MPCCrypto_initEcdsaSign.argtypes = [
    c_int, c_void_p, c_char_p, c_int, c_int, POINTER(c_void_p)]
libmpc.MPCCrypto_initEcdsaSign.restype = c_uint
libmpc.MPCCrypto_getResultEcdsaSign.argtypes = [
    c_void_p, c_char_p, POINTER(c_int)]
libmpc.MPCCrypto_getResultEcdsaSign.restype = c_uint
libmpc.MPCCrypto_verifyEcdsa.argtypes = [
    c_void_p, c_char_p, c_int, c_char_p, c_int]
libmpc.MPCCrypto_verifyEcdsa.restype = c_uint
libmpc.MPCCrypto_getEcdsaPublic.argtypes = [c_void_p, POINTER(c_void_p)]
libmpc.MPCCrypto_getEcdsaPublic.restype = c_uint


def initGenerateEcdsaKey(peer):
    ptr = c_void_p()
    test_rv(libmpc.MPCCrypto_initGenerateEcdsaKey(c_int(peer), byref(ptr)))
    return ptr


def initEcdsaSign(peer, share, buf, refresh):
    ctx = c_void_p()
    iRefresh = 1 if refresh else 0
    libmpc.MPCCrypto_initEcdsaSign(
        c_int(peer), share, c_char_p(buf), c_int(len(buf)), c_int(iRefresh), byref(ctx))
    return ctx


def getEcdsaSignResult(ctx):
    out_size = c_int()
    test_rv(libmpc.MPCCrypto_getResultEcdsaSign(ctx, None, byref(out_size)))
    sig = create_string_buffer(out_size.value)
    test_rv(libmpc.MPCCrypto_getResultEcdsaSign(ctx, sig, byref(out_size)))
    return sig.raw


def verifyEcdsa(pub_key, test, sig):
    test_rv(libmpc.MPCCrypto_verifyEcdsa(pub_key,
                                         c_char_p(test), c_int(len(test)), c_char_p(sig), c_int(len(sig))))


def getEcdsaPublic(key):
    pub_key = c_void_p()
    test_rv(libmpc.MPCCrypto_getEcdsaPublic(key, byref(pub_key)))
    return pub_key


class bip32_info_t(Structure):
    _fields_ = [("hardened", c_int),
                ("level", c_ubyte),
                ("child_number", c_uint),
                ("parent_fingerprint", c_uint),
                ("chain_code", c_ubyte * 32)
                ]


# BIP32 functions
libmpc.MPCCrypto_initDeriveBIP32.argtypes = [
    c_int, c_void_p, c_int, c_uint, POINTER(c_void_p)]
libmpc.MPCCrypto_initDeriveBIP32.restype = c_uint
libmpc.MPCCrypto_getResultDeriveBIP32.argtypes = [c_void_p, POINTER(c_void_p)]
libmpc.MPCCrypto_getResultDeriveBIP32.restype = c_uint
libmpc.MPCCrypto_serializePubBIP32.argtypes = [
    c_void_p, c_char_p, POINTER(c_int)]
libmpc.MPCCrypto_serializePubBIP32.restype = c_uint
libmpc.MPCCrypto_getBIP32Info.argtypes = [c_void_p, POINTER(bip32_info_t)]
libmpc.MPCCrypto_getBIP32Info.restype = c_uint


def getBIP32Info(share):
    bip32_info = bip32_info_t()
    test_rv(libmpc.MPCCrypto_getBIP32Info(share, bip32_info))
    return bip32_info


def initDeriveBIP32(peer, share_ptr, hardened, index):
    ctx = c_void_p()
    iHardend = 1 if hardened else 0
    test_rv(libmpc.MPCCrypto_initDeriveBIP32(
        c_int(peer), share_ptr, c_int(iHardend), c_uint(index), byref(ctx)))
    return ctx


def getDeriveBIP32Result(ctx):
    new_share_ptr = c_void_p()
    test_rv(libmpc.MPCCrypto_getResultDeriveBIP32(ctx, byref(new_share_ptr)))
    return new_share_ptr


def serializePubBIP32(share):
    out_size = c_int()
    test_rv(libmpc.MPCCrypto_serializePubBIP32(share, None, byref(out_size)))
    buf = create_string_buffer(out_size.value)
    test_rv(libmpc.MPCCrypto_serializePubBIP32(share, buf, byref(out_size)))
    return buf.raw.decode('ascii').rstrip('\0')


# ---------------  OO Wrapper -----------------------------
class MpcContext:
    def __init__(self, ctx):
        self.value = ctx

    def __enter__(self):
        pass

    def __exit__(self, type, value, tb):
        freeContext(self.value)

    def toBuf(self):
        return contextToBuf(self.value)


class MpcShare:
    def __init__(self, share=None):
        self.value = share

    def __enter__(self):
        pass

    def __exit__(self, type, value, tb):
        freeShare(self.value)

    def toBuf(self):
        return shareToBuf(self.value)


class MpcMessage:
    def __init__(self, msg):
        self.value = msg

    def __enter__(self):
        pass

    def __exit__(self, type, value, tb):
        freeMessage(self.value)

    def toBuf(self):
        return messageToBuf(self.value)


class MpcObject():
    def __init__(self, peer, share=None):
        self.peer = peer
        self.share = shareFromBuf(share) if share else None
        self.ctx = None

    def initRefresh(self):
        self.ctx = initRefreshKey(self.peer, self.share)

    def setShare(self, share):
        freeShare(self.share)
        self.share = share

    def __enter__(self):
        pass

    def free(self):
        freeShare(self.share)
        freeContext(self.ctx)
        self.share = None
        self.ctx = None

    def exportShare(self):
        return shareToBuf(self.share)

    def importShare(self, share):
        self.setShare(shareFromBuf(share))

    def __exit__(self, type, value, tb):
        self.free()


class GenericSecret(MpcObject):
    def initGenerate(self, bits):
        self.ctx = initGenerateGenericSecret(self.peer, bits)

    def initImport(self, data):
        self.ctx = initImportGenericSecret(self.peer, data)


class Eddsa(MpcObject):

    def initGenerate(self):
        self.ctx = initGenerateEddsaKey(self.peer)

    def initSign(self, data, refresh=False):
        self.ctx = initEddsaSign(self.peer, self.share, data, refresh)

    def getSignResult(self):
        res = getEddsaSignResult(self.ctx)
        freeContext(self.ctx)
        self.ctx = None
        return res

    def verify(self, data, signature):
        pub_key = getEddsaPublic(self.share)
        verifyEddsa(pub_key, data, signature)


class Ecdsa(MpcObject):
    def initGenerate(self):
        self.ctx = initGenerateEcdsaKey(self.peer)

    def initSign(self, data, refresh=False):
        self.ctx = initEcdsaSign(self.peer, self.share, data, refresh)

    def getSignResult(self):
        res = getEcdsaSignResult(self.ctx)
        freeContext(self.ctx)
        self.ctx = None
        return res

    def verify(self, data, signature):
        pub_key = getEcdsaPublic(self.share)
        verifyEcdsa(pub_key, data, signature)


class Bip32(MpcObject):
    def initDerive(self, fromObject, index, hardened=False):
        self.ctx = initDeriveBIP32(
            self.peer, fromObject.share, hardened, index)

    def getDeriveResult(self):
        self.share = getDeriveBIP32Result(self.ctx)

    def getInfo(self):
        return getBIP32Info(self.share)

    def serialize(self):
        return serializePubBIP32(self.share)
