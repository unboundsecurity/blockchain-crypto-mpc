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

public class Native
{
  static class IntRef
  {
    int value;
  }

  static
  {
    System.loadLibrary("mpc_crypto");
  }

  static native void freeShare(long handle);
  static native void freeContext(long handle);
  static native void freeMessage(long handle);

  static native int shareToBuf(long handle, byte[] out, IntRef outLen);
  static native int contextToBuf(long handle, byte[] out, IntRef outLen);
  static native int messageToBuf(long handle, byte[] out, IntRef outLen);

  static native int shareFromBuf(byte[] in, Share out);
  static native int contextFromBuf(byte[] in, Context out);
  static native int messageFromBuf(byte[] in, Message out);

  static native int shareInfo(long handle, Share.Info out);
  static native int contextInfo(long handle, Context.Info out);
  static native int messageInfo(long handle, Message.Info out);

  static native int step(long contextHandle, long messageHandle, Message out, IntRef outFlags);
  static native int getShare(long contextHandle, Share out);

  static native int initRefreshKey(int peer, long shareHandle, Context out);

  static native int getEddsaPublic(long shareHandle, byte[] out); // 32 bytes length
  static native int getResultEddsaSign(long contextHandle, byte[] out); // 64 bytes length
  static native int initGenerateEddsaKey(int peer, Context out);
  static native int initEddsaSign(int peer, long shareHandle, byte[] in, boolean refresh, Context out);
  static native int verifyEddsa(byte[] pubKey, byte[] in, byte[] signature);

  static native int getEcdsaPublic(long shareHandle, byte[] out, IntRef outLen);
  static native int getResultEcdsaSign(long contextHandle, byte[] out, IntRef outLen);
  static native int initGenerateEcdsaKey(int peer, Context out);
  static native int initEcdsaSign(int peer, long shareHandle, byte[] in, boolean refresh, Context out);
  static native int verifyEcdsa(byte[] pubKey, byte[] in, byte[] signature);

  static native int initGenerateGenericSecret(int peer, int bits, Context out);
  static native int initImportGenericSecret(int peer, byte[] secret, Context out);

  static native int initDeriveBIP32(int peer, long shareHandle, boolean hardened, int index, Context out);
  static native int getResultDeriveBIP32(long contextHandle, Share out);
  static native int getBIP32Info(long shareHandle, BIP32Info out);
  static native int serializePubBIP32(long shareHandle, char[] out, IntRef outLen);

  static native int initBackupEcdsaKey(int peer, long shareHandle, byte[] pubBackupKey, Context out);
  static native int getResultBackupEcdsaKey(long contextHandle, byte[] out, IntRef outLen);
  static native int verifyEcdsaBackupKey(byte[] pubBackupKey, byte[] pubKey, byte[] backup);
  static native int restoreEcdsaKey(byte[] prvBackupKey, byte[] pubKey, byte[] backup, byte[] out, IntRef outLen);

  static native int initBackupEddsaKey(int peer, long shareHandle, byte[] pubBackupKey, Context out);
  static native int getResultBackupEddsaKey(long contextHandle, byte[] out, IntRef outLen);
  static native int verifyEddsaBackupKey(byte[] pubBackupKey, byte[] pubKey, byte[] backup);
  static native int restoreEddsaKey(byte[] prvBackupKey, byte[] pubKey, byte[] backup, byte[] out); // 32 bytes length

}
