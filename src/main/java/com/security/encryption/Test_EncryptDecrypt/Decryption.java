package com.security.encryption.Test_EncryptDecrypt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.Security;
 
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
 
import java.util.Base64;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
@Path("/AsymString2")

public class Decryption {
 
     
    public static String decrypt (String privateKeyFilename, String encryptedData) {
 
        String outputData = null;
        try {
 
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
            String key = privateKeyFilename;
            AsymmetricKeyParameter privateKey = 
                (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.getDecoder().decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);
 
            byte[] messageBytes = Base64.getDecoder().decode(encryptedData);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
 
            System.out.println(new String(Base64.getDecoder().decode(key)));

            System.out.println(new String(hexEncodedCipher));
            outputData = new String(hexEncodedCipher);
 
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return outputData;
    }
 
    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
 
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
 
  /*  private static String readFileAsString(String filePath)
    throws java.io.IOException{
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(
                new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        System.out.println(fileData.toString());
        return fileData.toString();
    }
 */
    
    @POST
   	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
   	@Produces(MediaType.APPLICATION_JSON)	
   	public Response main(@FormParam ("Key")String keyString,
   						 @FormParam ("Text")String input) {
       	
           String Result=Decryption.decrypt(keyString, input);
   		String Message = "{\"Encrypted String\": \""+Result+"\"}";

           return Response
   	  	          .status(Response.Status.OK)
   	  	          .entity(Message)
   	  	          .type(MediaType.APPLICATION_JSON)
   	  	          .build();	    	
   }

}

