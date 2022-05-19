/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package argon2hashpassword;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;



/**
 * A class to hash password and verify if the password matches with the giving hash
 * Singleton class
 * @author Basile
 */
public class Argon2 {
    private final int DEFAULT_HASH_LENGTH = 32;
    private final int DEFAULT_PARALLELISM = 1;
    private final int DEFAULT_MEMORY = 50_000;
    private final int DEFAULT_ITERATIONS = 3;
    
    private byte[] generateSalt;
    
    /**
     * Singleton
     * @return instance of Argon2
     */
    public static Argon2 getInstance() {
        return Argon2Holder.INSTANCE;
    }
   
    /**
     * Singleton
     */
    private static class Argon2Holder {
        private static final Argon2 INSTANCE = new Argon2();
    }

    /**
     * Simple getter for generate salt
     * @return the generate salt
     */
    public byte[] getGenerateSalt() {
        return generateSalt;
    }
    
    /**
     * Facade method without giving salt
     * Return the password which has been hash
     * @param password String : user password
     * @return password that has been hash
     */
    public String generateHashArgon2Password(String password){
        generateSalt = generateSalt16Byte();
        return generateHashArgon2Password(password, generateSalt);
    }
    
    /**
     * Generate Hash Password give in parameter with salt (randomness)
     * And return the hash
     * @param password String: password of user
     * @param salt Byte[] : array of byte
     * @return the password hash
     */
    private String generateHashArgon2Password(String password, byte[] salt){
        Argon2BytesGenerator genArgon = new Argon2BytesGenerator();
        
        Argon2Parameters paramArgon = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(DEFAULT_ITERATIONS)
                .withMemoryAsKB(DEFAULT_MEMORY)
                .withParallelism(DEFAULT_PARALLELISM)
                .withSalt(salt).build();
        
        genArgon.init(paramArgon);
        byte[] result = new byte[DEFAULT_HASH_LENGTH];
        
        genArgon.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
        return convertByteToString(result);
    }
    
    /**
     * Check if the hash password in the file/db is the same that the password gave in parameter
     * @param hash String : Hash password sotre
     * @param salt Byte[] : Salt that has been save for more secure hash function
     * @param password String : password gave
     * @return true if hash and password are the same else false
     */
    public boolean isSamePassword(String hash, byte[] salt, String password){
        return (hash == null ? (generateHashArgon2Password(password, salt)) == null : hash.equals(generateHashArgon2Password(password, salt)));
    }
    
    /**
     * Generate a random salt of 16 bytes
     * And return it
     * @return random Salt 16 bytes
     */
    private byte[] generateSalt16Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Convert array of byte to string
     * @param input Byte[] : array of byte to convert
     * @return String convertion
     */
    private String convertByteToString(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }
}
