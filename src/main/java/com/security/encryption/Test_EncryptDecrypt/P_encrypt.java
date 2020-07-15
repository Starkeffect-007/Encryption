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
import javax.ws.rs.core.MediaType;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.ws.rs.*;
@Path("/P_encrypt")
public class P_encrypt 
{

    Cipher cipher;
    byte[] salt = {
            (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
            (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
        };
    int iterationCount = 10;

    public P_encrypt() {
    }
    

    public String encrypt(String secretKey, String plainText)
            throws Exception {
    	Security.addProvider(new BouncyCastleProvider());
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES","BC").generateSecret(keySpec);
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
        cipher = Cipher.getInstance(key.getAlgorithm(),"BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        String charSet = "UTF-8";
        byte[] in = plainText.getBytes(charSet);
        byte[] out = cipher.doFinal(in);
        String encStr = new String(Base64.getEncoder().encode(out));
        return encStr;
    }
    
     @POST
     @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
     @Produces(MediaType.APPLICATION_JSON)
    public static String main(@FormParam ("Pass")String key,@FormParam ("text")String plain) throws Exception {
    	P_encrypt cryptotil=new P_encrypt();
    	String text=null;
    	text=cryptotil.encrypt(key, plain);
		return text;
    }
     @GET
     @Produces(MediaType.TEXT_PLAIN)
      public String getIT()
          {return "No Method Found"; }

}