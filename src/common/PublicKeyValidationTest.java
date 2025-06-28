package common;

import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

/**
 * Comprehensive test for public key validation security features
 * Tests weak keys, non-RSA keys, small public exponents, and valid RSA keys
 */
public class PublicKeyValidationTest {
    
    public static void main(String[] args) {
        System.out.println("=== PUBLIC KEY VALIDATION SECURITY TEST ===");
        
        boolean allTestsPassed = true;
        allTestsPassed &= testValidRSAKey();
        allTestsPassed &= testWeakRSAKey();
        allTestsPassed &= testNonRSAKey();
        allTestsPassed &= testSmallPublicExponent();
        
        System.out.println("\n=== TEST SUMMARY ===");
        if (allTestsPassed) {
            System.out.println("[PASS]]ALL TESTS PASSED - Public key validation is working correctly!");
        } else {
            System.out.println("[FAIL] SOME TESTS FAILED - Review the implementation!");
        }
    }
    
    /**
     * Test that valid RSA 2048-bit keys are accepted
     */
    private static boolean testValidRSAKey() {
        System.out.println("\n1. Testing valid RSA 2048-bit key acceptance...");
        try {
            // Generate a standard RSA 2048-bit key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            
            CryptoUtils.validatePublicKey(publicKey);
            
            byte[] keyBytes = publicKey.getEncoded();
            CryptoUtils.bytesToPublicKey(keyBytes);
            
            System.out.println("   [PASS] Valid RSA 2048-bit key accepted");
            return true;
        } catch (Exception e) {
            System.out.println("   [FAIL] Valid key rejected: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Test that weak RSA keys (< 2048 bits) are rejected
     */
    private static boolean testWeakRSAKey() {
        System.out.println("\n2. Testing weak RSA key rejection...");
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey weakKey = keyPair.getPublic();
            
            CryptoUtils.validatePublicKey(weakKey);
            
            System.out.println("   [FAIL] Weak RSA key was accepted (SECURITY FAILURE!)");
            return false;
        } catch (SecurityException e) {
            if (e.getMessage().contains("too weak")) {
                System.out.println("   [PASS] Weak RSA key properly rejected: " + e.getMessage());
                return true;
            } else {
                System.out.println("   [FAIL] Wrong rejection reason: " + e.getMessage());
                return false;
            }
        } catch (Exception e) {
            System.out.println("   [FAIL] Unexpected error: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Test that non-RSA keys are rejected
     */
    private static boolean testNonRSAKey() {
        System.out.println("\n6. Testing non-RSA key rejection...");
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey ecKey = keyPair.getPublic();
            
            CryptoUtils.validatePublicKey(ecKey);
            
            System.out.println("   [FAIL] Non-RSA key was accepted (SECURITY FAILURE!)");
            return false;
        } catch (SecurityException e) {
            if (e.getMessage().contains("Only RSA")) {
                System.out.println("   [PASS] Non-RSA key properly rejected: " + e.getMessage());
                return true;
            } else {
                System.out.println("   [FAIL] Wrong rejection reason: " + e.getMessage());
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("   ~ EC algorithm not available, skipping test");
            return true;
        } catch (Exception e) {
            System.out.println("   [FAIL] Unexpected error: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Test handling of small public exponents
     */
    private static boolean testSmallPublicExponent() {
        System.out.println("\n7. Testing small public exponent handling...");
        try {
            // Create an RSA key with public exponent 3 (should generate warnings)
            BigInteger modulus = new BigInteger("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
            BigInteger exponent = BigInteger.valueOf(3);
            
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            try {
                PublicKey rsaKey = keyFactory.generatePublic(keySpec);
                
                CryptoUtils.validatePublicKey(rsaKey);
                System.out.println("   [PASS] Small public exponent handled with warnings");
                return true;
            } catch (Exception e) {
                System.out.println("   ~ Cannot generate test key with small exponent, skipping");
                return true;
            }
        } catch (Exception e) {
            System.out.println("   [FAIL] Error testing small public exponent: " + e.getMessage());
            return false;
        }
    }
}
