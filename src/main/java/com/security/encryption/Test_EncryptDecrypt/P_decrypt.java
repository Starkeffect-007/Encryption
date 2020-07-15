package com.security.encryption.Test_EncryptDecrypt;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
@Path("/P_decrypt")
public class P_decrypt 
{

    Cipher Decrypt_cipher;
    // 8-byte Salt
    byte[] salt = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
    };
    // Iteration count
    int iterationCount = 10;

    public P_decrypt() {

    }

    
    public String decrypt(String secretKey, String encryptedText)
            throws Exception {
    	Security.addProvider(new BouncyCastleProvider());
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES","BC").generateSecret(keySpec);
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
        Decrypt_cipher = Cipher.getInstance(key.getAlgorithm(),"BC");
        Decrypt_cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        byte[] enc = Base64.getDecoder().decode(encryptedText);
        byte[] utf8 = Decrypt_cipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, charSet);
        return plainStr;
    }    
   
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
   public static String main(@FormParam("Pass") String key,@FormParam("text") String enc) throws Exception {
   	P_decrypt dec=new P_decrypt();
       String plain=dec.decrypt(key, enc);
		return plain; 
   }
    @GET
    @Produces(MediaType.TEXT_PLAIN)
     public String getIT()
         {return "No Method Found"; }

}