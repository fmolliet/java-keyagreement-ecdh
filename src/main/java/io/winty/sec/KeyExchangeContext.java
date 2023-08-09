package io.winty.sec;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyExchangeContext {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final String CURVE = "secp256r1";
    private static final String ALGO = "AES/GCM/NoPadding";
    
    private SecretKey secret;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    private Cipher cipher; 
    
    public KeyExchangeContext() throws GeneralSecurityException{
        cipher = Cipher.getInstance(ALGO);
        ECGenParameterSpec spec = new ECGenParameterSpec(CURVE);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(spec, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }
    
    public String getPublicKey() {
        return encodeToHex(publicKey.getEncoded());
    }
    /**
     * 
     * @param serverPublicKey Base64 public key
     * @throws GeneralSecurityException
     * @throws IllegalStateException
     */
    public void keyAgreement(String serverPublicKey) throws GeneralSecurityException, IllegalStateException {
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(getPublicKeyFrom(serverPublicKey), true);
        secret = new SecretKeySpec(keyAgreement.generateSecret(), "AES");
    }

    private PublicKey  getPublicKeyFrom(String publicKey) throws GeneralSecurityException {
        return getPublicKeyFrom(decodeFromHex(publicKey));
    }
    
    private PublicKey  getPublicKeyFrom(byte[] publicKey) throws GeneralSecurityException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
    
    public String encrypt(String plaintext) throws GeneralSecurityException {
        
        byte[] nonce = generateRandomNonce(12); // Nonce de 12 bytes
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secret, spec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(UTF_8));
        byte[] combined = new byte[nonce.length + encryptedBytes.length];
        
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(encryptedBytes, 0, combined, nonce.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }
    
    public String decrypt(String encryptedText) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        byte[] combined = Base64.getDecoder().decode(encryptedText);
        byte[] nonce = new byte[12];
        byte[] encryptedBytes = new byte[combined.length - nonce.length];

        System.arraycopy(combined, 0, nonce, 0, nonce.length);
        System.arraycopy(combined, nonce.length, encryptedBytes, 0, encryptedBytes.length);
        
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secret, spec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, UTF_8);
    }
    
    private static byte[] generateRandomNonce(int size) {
        byte[] nonce = new byte[size];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static String encodeToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] decodeFromHex(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }
}
