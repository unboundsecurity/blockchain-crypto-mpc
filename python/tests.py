import sys
import os
import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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


def exec_client_server(objClient, objServer):
    client_finished = False
    server_finished = False
    message_buf = None
    while not client_finished or not server_finished:
        if not client_finished:
            client_finished, message_buf = perform_step(objClient, message_buf)

        if message_buf is None:
            break

        if not server_finished:
            server_finished, message_buf = perform_step(objServer, message_buf)


def generic_secret_gen():
    print("test_generic_secret_gen...")
    clientObj = mpc_crypto.GenericSecret(CLIENT)
    serverObj = mpc_crypto.GenericSecret(SERVER)
    clientObj.initGenerate(256)
    serverObj.initGenerate(256)
    exec_client_server(clientObj, serverObj)
    print(" ok")
    return clientObj, serverObj


def generic_secret_import(value=None):
    print("test_generic_secret_import...")
    if not value:
        value = os.urandom(32)
    clientObj = mpc_crypto.GenericSecret(CLIENT)
    serverObj = mpc_crypto.GenericSecret(SERVER)
    clientObj.initImport(value)
    serverObj.initImport(value)
    exec_client_server(clientObj, serverObj)
    print(" ok")
    return clientObj, serverObj


def eddsa_gen():
    print("test_eddsa_gen...")
    clientObj = mpc_crypto.Eddsa(CLIENT)
    serverObj = mpc_crypto.Eddsa(SERVER)
    clientObj.initGenerate()
    serverObj.initGenerate()
    exec_client_server(clientObj, serverObj)
    print(" ok")
    return clientObj, serverObj


def eddsa_sign(clientObj, serverObj):
    print("test_eddsa_sign...")
    test_data = b"123456"
    clientObj.initSign(test_data, True)
    serverObj.initSign(test_data, True)
    exec_client_server(clientObj, serverObj)
    sig = clientObj.getSignResult()
    clientObj.verify(test_data, sig)
    print("ok")


def ecdsa_gen():
    print("test_ecdsa_gen...")
    clientObj = mpc_crypto.Ecdsa(CLIENT)
    serverObj = mpc_crypto.Ecdsa(SERVER)
    clientObj.initGenerate()
    serverObj.initGenerate()
    exec_client_server(clientObj, serverObj)
    print(" ok")
    return clientObj, serverObj


def ecdsa_sign(clientObj, serverObj):
    print("test_ecdsa_sign...")
    test_data = b"123456"
    clientObj.initSign(test_data, True)
    serverObj.initSign(test_data, True)
    exec_client_server(clientObj, serverObj)
    sig = clientObj.getSignResult()
    clientObj.verify(test_data, sig)
    print("ok")


def refresh_shares(clientObj, serverObj):
    print("test_refresh...")
    clientObj.initRefresh()
    serverObj.initRefresh()
    exec_client_server(clientObj, serverObj)
    print(" ok")


def bip_derive(srcClient, srcServer, hardened, index, test):
    clientObj = mpc_crypto.Bip32(CLIENT)
    serverObj = mpc_crypto.Bip32(SERVER)
    clientObj.initDerive(srcClient, index, hardened)
    serverObj.initDerive(srcServer, index, hardened)
    exec_client_server(clientObj, serverObj)
    clientObj.getDeriveResult()
    serverObj.getDeriveResult()

    assert clientObj.serialize() == test
    return clientObj, serverObj


def test_bip():
    seed = "000102030405060708090a0b0c0d0e0f"
    seedClient, seedServer = generic_secret_import(
        binascii.unhexlify(seed))
    with seedClient, seedServer:
        m_cl, m_sr = bip_derive(seedClient, seedServer, False, 0,
                                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        m_0H_cl, m_0H_sr = bip_derive(
            m_cl, m_sr, True, 0, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
        m_0H_1_cl, m_0H_1_sr = bip_derive(m_0H_cl, m_0H_sr, False, 1,
                                          "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    # test_bip_derive(m_0H_1, True, 2, m_0H_1_2H,
    #                 "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")
    # test_bip_derive(m_0H_1_2H, False, 2, m_0H_1_2H_2,
    #                 "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
    # test_bip_derive(m_0H_1_2H_2, False, 1000000000, m_0H_1_2H_2_1000000000,
    #                 "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")


def gen_rsa_test_key():
    backup_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_prv_der = backup_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    backup_pub_key = backup_key.public_key()
    rsa_pub_der = backup_pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return rsa_prv_der, rsa_pub_der


def eddsa_backup(clientObj, serverObj):
    print("test_eddsa_backup...")
    rsa_prv_der, rsa_pub_der = gen_rsa_test_key()
    clientObj.initBackup(rsa_pub_der)
    serverObj.initBackup(rsa_pub_der)
    exec_client_server(clientObj, serverObj)
    backup = clientObj.getBackupResult()

    pub_eddsa_key = clientObj.getPublic()
    mpc_crypto.verifyEddsaBackupKey(rsa_pub_der, pub_eddsa_key, backup)
    prv_eddsa_key = mpc_crypto.restoreEddsaKey(
        rsa_prv_der, pub_eddsa_key, backup)


def ecdsa_backup(clientObj, serverObj):
    print("test_ecdsa_backup...")
    rsa_prv_der, rsa_pub_der = gen_rsa_test_key()
    clientObj.initBackup(rsa_pub_der)
    serverObj.initBackup(rsa_pub_der)
    exec_client_server(clientObj, serverObj)
    backup = clientObj.getBackupResult()

    pub_ecdsa_key = clientObj.getPublic()
    mpc_crypto.verifyEcdsaBackupKey(rsa_pub_der, pub_ecdsa_key, backup)
    prv_ecdsa_key = mpc_crypto.restoreEcdsaKey(
        rsa_prv_der, pub_ecdsa_key, backup)


def test_eddsa():
    eddsaKeyClient, eddsaKeyServer = eddsa_gen()
    refresh_shares(eddsaKeyClient, eddsaKeyServer)
    eddsa_sign(eddsaKeyClient, eddsaKeyServer)
    eddsa_backup(eddsaKeyClient, eddsaKeyServer)


def test_ecdsa():
    ecdsaKeyClient, ecdsaKeyServer = ecdsa_gen()
    refresh_shares(ecdsaKeyClient, ecdsaKeyServer)
    ecdsa_sign(ecdsaKeyClient, ecdsaKeyServer)
    ecdsa_backup(ecdsaKeyClient, ecdsaKeyServer)


def test_generic_secret():
    genSecClient, genSecServer = generic_secret_gen()
    genSecClient2, genSecServer2 = generic_secret_import()


if __name__ == "__main__":
    try:
        test_eddsa()
        test_bip()
        test_ecdsa()
        test_generic_secret()
    except mpc_crypto.MPCException as e:
        sys.exit("MPC Error - " + hex(e.error_code))
    print('OOTest Unbound OSS crypto MPC - OK')
