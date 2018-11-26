/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3.
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *
 *     Copyright (C) 2018, Unbound Tech Ltd.
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.unboundTech.mpc;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Share implements AutoCloseable
{
  long handle = 0;

  public static class Info
  {
    public long UID = 0;
    public int type = 0;
  }

  @Override
  public void close()
  {
    if (handle!=0) Native.freeShare(handle);
    handle = 0;
  }

  public byte[] toBuf() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.shareToBuf(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.shareToBuf(handle, out, outLen));
    return out;
  }

  public static Share fromBuf(byte[] in) throws MPCException
  {
    Share out = new Share();
    MPCException.check(Native.shareFromBuf(in, out));
    return out;
  }

  public Info getInfo() throws MPCException
  {
    Info out = new Info();
    MPCException.check(Native.shareInfo(handle, out));
    return out;
  }

  public byte[] getEddsaPublic() throws MPCException
  {
    byte[] out = new byte[32];
    MPCException.check(Native.getEddsaPublic(handle, out));
    return out;
  }

  public static boolean verifyEddsa(byte[] pubKey, byte[] in, byte[] signature)
  {
    return 0==Native.verifyEddsa(pubKey, in, signature);
  }

  public static boolean verifyEcdsa(ECPublicKey pubKey, byte[] in, byte[] signature)
  {
    return 0==Native.verifyEcdsa(pubKey.getEncoded(), in, signature);
  }

  public ECPublicKey getEcdsaPublic() throws MPCException, NoSuchAlgorithmException, InvalidKeySpecException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.getEcdsaPublic(handle, null, outLen));
    byte[] encoded = new byte[outLen.value];
    MPCException.check(Native.getEcdsaPublic(handle, encoded, outLen));

    X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(spec);
  }

  public BIP32Info getBIP32Info() throws MPCException
  {
    BIP32Info out = new BIP32Info();
    MPCException.check(Native.getBIP32Info(handle, out));
    return out;
  }

  public String serializePubBIP32() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.serializePubBIP32(handle, null, outLen));
    char[] chars = new char[outLen.value];
    MPCException.check(Native.serializePubBIP32(handle, chars, outLen));
    return new String(chars);
  }

  public static boolean verifyEcdsaBackupKey(RSAPublicKey pubBackupKey, ECPublicKey pubKey, byte[] backup) throws MPCException
  {
    return 0 == Native.verifyEcdsaBackupKey(pubBackupKey.getEncoded(), pubKey.getEncoded(), backup);
  }

  public static ECPrivateKey restoreEcdsaKey(RSAPrivateKey prvBackupKey, ECPublicKey pubKey, byte[] backup) throws MPCException, NoSuchAlgorithmException, InvalidKeySpecException
  {
    byte[] prvBackupKeyEncoded = prvBackupKey.getEncoded();

    byte[] pubKeyEncoded = pubKey.getEncoded();

    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.restoreEcdsaKey(prvBackupKeyEncoded, pubKeyEncoded, backup, null, outLen));
    byte[] eccPrivateKeyEncoded = new byte[outLen.value];
    MPCException.check(Native.restoreEcdsaKey(prvBackupKeyEncoded, pubKeyEncoded, backup, eccPrivateKeyEncoded, outLen));

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec (eccPrivateKeyEncoded);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return (ECPrivateKey) kf.generatePrivate(spec);
  }

  public static boolean verifyEddsaBackupKey(RSAPublicKey pubBackupKey, byte[] pubKey, byte[] backup) throws MPCException
  {
    return 0 == Native.verifyEddsaBackupKey(pubBackupKey.getEncoded(), pubKey, backup);
  }

  public static byte[] restoreEddsaKey(RSAPrivateKey prvBackupKey, byte[] pubKey, byte[] backup) throws MPCException
  {
    byte[] prvBackupKeyEncoded = prvBackupKey.getEncoded();

    byte[] out = new byte[32];
    MPCException.check(Native.restoreEddsaKey(prvBackupKeyEncoded, pubKey, backup, out));

    return out;
  }

  public Context initRefreshKey(int peer) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initRefreshKey(peer, handle, out));
    return out;
  }

  public Context initEddsaSign(int peer, byte[] in, boolean refresh) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initEddsaSign(peer, handle, in, refresh, out));
    return out;
  }

  public Context initEcdsaSign(int peer, byte[] in, boolean refresh) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initEcdsaSign(peer, handle, in, refresh, out));
    return out;
  }

  public Context initDeriveBIP32(int peer, boolean hardened, int index) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initDeriveBIP32(peer, handle, hardened, index, out));
    return out;
  }

  public Context initBackupEcdsaKey(int peer, RSAPublicKey pubBackupKey) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initBackupEcdsaKey(peer, handle, pubBackupKey.getEncoded(), out));
    return out;
  }

  public Context initBackupEddsaKey(int peer, RSAPublicKey pubBackupKey) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initBackupEddsaKey(peer, handle, pubBackupKey.getEncoded(), out));
    return out;
  }


}
