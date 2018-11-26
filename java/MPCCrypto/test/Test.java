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
import com.unboundTech.mpc.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Test
{
  private static class TestShare implements AutoCloseable
  {
    Share client = null;
    Share server = null;

    @Override
    public void close() throws Exception
    {
      if (client!=null) client.close();
      if (server!=null) server.close();
      client = null;
      server = null;
    }
  }

  private static class TestContext implements AutoCloseable
  {
    Context client = null;
    Context server = null;

    @Override
    public void close() throws Exception
    {
      if (client!=null) client.close();
      if (server!=null) server.close();
      client = null;
      server = null;
    }
  }

  static class TestStep implements AutoCloseable
  {
    byte[] messageBuf = null;
    public Share share = null;
    public Context context = null;

    TestStep(Share share, Context context)
    {
      this.share = share;
      this.context = context;
    }

    boolean step() throws Exception
    {
      boolean finished = false;

      try (
        Message inMessage = (messageBuf==null) ? null : Message.fromBuf(messageBuf);
        Context.MessageAndFlags messageAndFlags = context.step(inMessage))
      {
        byte[] contextBuf = context.toBuf();
        context.close();
        context = Context.fromBuf(contextBuf);

        finished = messageAndFlags.protocolFinished;

        if (messageAndFlags.shareChanged)
        {
          if (share!=null) share.close();
          share = context.getShare();

          byte[] shareBuf = share.toBuf();
          share.close();
          share = Share.fromBuf(shareBuf);
        }

        if (messageAndFlags.message!=null)
        {
          messageBuf = messageAndFlags.message.toBuf();
        }
      }

      return finished;
    }

    @Override
    public void close() throws Exception
    {
      if (share!=null) share.close();
      if (context!=null) context.close();
      share = null;
      context = null;
    }
  }

  private static void testClientServer(TestShare testShare, TestContext testContext) throws Exception
  {
    boolean clientFinished = false;
    boolean serverFinished = false;

    try (
      TestStep clientStep = new TestStep(testShare.client, testContext.client);
      TestStep serverStep = new TestStep(testShare.server, testContext.server))
    {
      testShare.client = testShare.server = null;
      testContext.client = testContext.server = null;

      while (!clientFinished || !serverFinished)
      {
        if (!clientFinished)
        {
          clientFinished = clientStep.step();
        }

        if (clientStep.messageBuf==null) break;
        serverStep.messageBuf = clientStep.messageBuf;
        clientStep.messageBuf = null;

        if (!serverFinished)
        {
          serverFinished = serverStep.step();
        }

        clientStep.messageBuf = serverStep.messageBuf;
        serverStep.messageBuf = null;
      }

      testShare.client = clientStep.share;
      testShare.server = serverStep.share;
      testContext.client = clientStep.context;
      testContext.server = serverStep.context;

      clientStep.share = serverStep.share = null;
      clientStep.context = serverStep.context = null;
    }
  }

  private static TestShare testEddsaGen() throws Exception
  {
    System.out.print("testEddsaGen...");
    TestShare testShare = new TestShare();

    try (TestContext testContext = new TestContext())
    {
      testContext.client = Context.initGenerateEddsaKey(1);
      testContext.server = Context.initGenerateEddsaKey(2);

      testClientServer(testShare, testContext);
    }

    System.out.println(" ok");
    return testShare;
  }

  private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException
  {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    return keyGen.genKeyPair();
  }

  private static void testEddsaBackup(TestShare eddsaKey) throws Exception
  {
    System.out.print("testEddsaBackup...");

    KeyPair rsaKeyPair = generateRsaKeyPair();

    try (TestContext testContext = new TestContext())
    {
      testContext.client = eddsaKey.client.initBackupEddsaKey(1, (RSAPublicKey) rsaKeyPair.getPublic());
      testContext.server = eddsaKey.server.initBackupEddsaKey(2, (RSAPublicKey) rsaKeyPair.getPublic());
      testClientServer(eddsaKey, testContext);

      byte[] backup = testContext.client.getResultBackupEddsaKey();
      byte[] eddsaPubKey = eddsaKey.client.getEddsaPublic();

      if (!Share.verifyEddsaBackupKey((RSAPublicKey)rsaKeyPair.getPublic(), eddsaPubKey, backup))
      {
        throw new Exception("verifyEddsaBackupKey failed");
      }

      byte[] eddsaPrvKey = Share.restoreEddsaKey((RSAPrivateKey) rsaKeyPair.getPrivate(), eddsaPubKey, backup);
    }

    System.out.println(" ok");
  }

  static void testEddsaSign(TestShare testKey) throws Exception
  {
    System.out.print("testEddsaSign...");
    byte[] test = "123456".getBytes();

    try (TestContext testContext = new TestContext())
    {
      testContext.client = testKey.client.initEddsaSign(1, test, true);
      testContext.server = testKey.server.initEddsaSign(2, test, true);
      testClientServer(testKey, testContext);

      byte[] signature = testContext.client.getResultEddsaSign();
      byte[] pubKey = testKey.client.getEddsaPublic();

      if (!Share.verifyEddsa(pubKey, test, signature))
      {
        throw new Exception("verifyEddsa failed");
      }
    }

    System.out.println(" ok");
  }

  static void testRefresh(TestShare testKey) throws Exception
  {
    System.out.print("testRefresh...");

    try (TestContext testContext = new TestContext())
    {
      testContext.client = testKey.client.initRefreshKey(1);
      testContext.server = testKey.server.initRefreshKey(2);
      testClientServer(testKey, testContext);
    }

    System.out.println(" ok");
  }

  static TestShare testGenericSecretImport() throws Exception
  {
    System.out.print("testGenericSecretImport...");
    byte[] testValue = "123456".getBytes();

    TestShare testShare = new TestShare();
    try (TestContext testContext = new TestContext())
    {
      testContext.client = Context.initImportGenericSecret(1, testValue);
      testContext.server = Context.initImportGenericSecret(2, testValue);
      testClientServer(testShare, testContext);
    }
    System.out.println(" ok");
    return testShare;
  }

  static TestShare testGenericSecretGen() throws Exception
  {
    System.out.print("testGenericSecretGen...");

    TestShare testShare = new TestShare();
    try (TestContext testContext = new TestContext())
    {
      testContext.client = Context.initGenerateGenericSecret(1, 256);
      testContext.server = Context.initGenerateGenericSecret(2, 256);
      testClientServer(testShare, testContext);
    }
    System.out.println(" ok");
    return testShare;
  }

  static TestShare testEcdsaGen() throws Exception
  {
    System.out.print("testEcdsaGen...");

    TestShare testShare = new TestShare();
    try (TestContext testContext = new TestContext())
    {
      testContext.client = Context.initGenerateEcdsaKey(1);
      testContext.server = Context.initGenerateEcdsaKey(2);
      testClientServer(testShare, testContext);
    }
    System.out.println(" ok");
    return testShare;
  }


  private static void testEcdsaBackup(TestShare eddsaKey) throws Exception
  {
    System.out.print("testEcdsaBackup...");

    KeyPair rsaKeyPair = generateRsaKeyPair();

    try (TestContext testContext = new TestContext())
    {
      testContext.client = eddsaKey.client.initBackupEcdsaKey(1, (RSAPublicKey) rsaKeyPair.getPublic());
      testContext.server = eddsaKey.server.initBackupEcdsaKey(2, (RSAPublicKey) rsaKeyPair.getPublic());
      testClientServer(eddsaKey, testContext);

      byte[] backup = testContext.client.getResultBackupEcdsaKey();
      ECPublicKey ecdsaPubKey = eddsaKey.client.getEcdsaPublic();

      if (!Share.verifyEcdsaBackupKey((RSAPublicKey)rsaKeyPair.getPublic(), ecdsaPubKey, backup))
      {
        throw new Exception("verifyEcdsaBackupKey failed");
      }

      ECPrivateKey ecdsaPrivateKey = Share.restoreEcdsaKey((RSAPrivateKey) rsaKeyPair.getPrivate(), ecdsaPubKey, backup);
    }

    System.out.println(" ok");
  }

  static void testEcdsaSign(TestShare testKey) throws Exception
  {
    System.out.print("testEcdsaSign...");
    byte[] test = "123456".getBytes();

    try (TestContext testContext = new TestContext())
    {
      testContext.client = testKey.client.initEcdsaSign(1, test, true);
      testContext.server = testKey.server.initEcdsaSign(2, test, true);
      testClientServer(testKey, testContext);

      byte[] signature = testContext.client.getResultEcdsaSign();
      ECPublicKey pubKey = testKey.client.getEcdsaPublic();
      Signature sig = Signature.getInstance("NoneWithECDSA");
      sig.initVerify(pubKey);
      sig.update(test);
      if (!sig.verify(signature))
      {
        throw new Exception("verifyEcdsa failed");
      }
    }

    System.out.println(" ok");
  }

  static byte[] hexToBin(String str)
  {
     int len = str.length();
     byte[] out = new byte[len / 2];

     for (int i = 0; i < len; i = i + 2)
     {
       out[i / 2] = (byte) Integer.parseInt(str.substring(i, i+2), 16);
     }
     return out;
    }

  static void testBIP32Serialize(TestShare testShare, String test) throws Exception
  {
    String s = testShare.client.serializePubBIP32();
    if (!s.equals(test))
    {
      throw new Exception("testBIP32Serialize failed");
    }
  }

  static TestShare testBIP32Master(String seed, String test)  throws Exception
  {
    System.out.print("testBIP32Master...");
    byte[] seedValue = hexToBin(seed);

    TestShare testShare = new TestShare();

    try (TestShare testSeedShare = new TestShare())
    {
      try (TestContext testContext = new TestContext())
      {
        testContext.client = Context.initImportGenericSecret(1, seedValue);
        testContext.server = Context.initImportGenericSecret(2, seedValue);
        testClientServer(testSeedShare, testContext);
      }

      try (TestContext testContext = new TestContext())
      {
        testContext.client = testSeedShare.client.initDeriveBIP32(1, false, 0);
        testContext.server = testSeedShare.server.initDeriveBIP32(2, false, 0);
        testClientServer(testSeedShare, testContext);

        testShare.client = testContext.client.getResultDeriveBIP32();
        testShare.server = testContext.server.getResultDeriveBIP32();
      }

      testBIP32Serialize(testShare, test);
    }
    System.out.println(" ok");
    return testShare;
  }

  static TestShare testBIP32Derive(TestShare src, boolean hardened, int index, String test) throws Exception
  {
    System.out.print("testBIP32Derive...");
    TestShare testShare = new TestShare();
    try (TestContext testContext = new TestContext())
    {
      testContext.client = src.client.initDeriveBIP32(1, hardened, index);
      testContext.server = src.server.initDeriveBIP32(2, hardened, index);
      testClientServer(src, testContext);

      testShare.client = testContext.client.getResultDeriveBIP32();
      testShare.server = testContext.server.getResultDeriveBIP32();
    }

    testBIP32Serialize(testShare, test);
    System.out.println(" ok");
    return testShare;
  }


  static void testBIP() throws Exception
  {
    {
      TestShare m = testBIP32Master("000102030405060708090a0b0c0d0e0f", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
      TestShare m_0H = testBIP32Derive(m, true, 0, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
      TestShare m_0H_1 = testBIP32Derive(m_0H, false, 1, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
      TestShare m_0H_1_2H = testBIP32Derive(m_0H_1, true, 2, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
      TestShare m_0H_1_2H_2 = testBIP32Derive(m_0H_1_2H, false, 2, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");
      TestShare m_0H_1_2H_2_1000000000 = testBIP32Derive(m_0H_1_2H_2, false, 1000000000, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    }

    {
      TestShare m = testBIP32Master("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
      TestShare m_0 = testBIP32Derive(m, false, 0, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
      TestShare m_0_2147483647H = testBIP32Derive(m_0, true, 2147483647, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
      TestShare m_0_2147483647H_1 = testBIP32Derive(m_0_2147483647H, false, 1, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
      TestShare m_0_2147483647H_1_2147483646H = testBIP32Derive(m_0_2147483647H_1, true, 2147483646, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
      TestShare m_0_2147483647H_1_2147483646H_2  = testBIP32Derive(m_0_2147483647H_1_2147483646H, false, 2, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    }

    {
      TestShare m = testBIP32Master("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
      TestShare m_0 = testBIP32Derive(m, true, 0, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
    }
  }

  public static void main(String args[])
  {
    try
    {
      TestShare eddsaKey = testEddsaGen();
      testEddsaBackup(eddsaKey);
      for (int i=0; i<3; i++)
      {
        testEddsaSign(eddsaKey);
        testRefresh(eddsaKey);
      }

      TestShare secretKey1 = testGenericSecretImport();
      TestShare secretKey2 = testGenericSecretGen();
      for (int i = 0; i<3; i++)
      {
        testRefresh(secretKey2);
      }

      TestShare ecdsaKey = testEcdsaGen();
      testEcdsaBackup(ecdsaKey);

      for (int i=0; i<3; i++)
      {
        testEcdsaSign(ecdsaKey);
        testRefresh(ecdsaKey);
      }

      testBIP();

      System.out.println("\nAll tests successfully finished.");
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }

}
