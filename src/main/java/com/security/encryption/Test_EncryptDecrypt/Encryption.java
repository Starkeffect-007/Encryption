package com.security.encryption.Test_EncryptDecrypt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.Security;
 
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
 
import java.util.Base64;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
@Path("/AsymString")

public class Encryption {
 
 /*   public static void main(String[] args)
    {
 
        String publicKeyFilename = null;
        String inputData = null;
        
        Encryption Encryption = new Encryption();
 
        if (args.length < 2)
        {
            System.err.println("Usage: java "+ Encryption.getClass().getName()+
            " Public_Key_Filename Input_String_data");
            System.exit(1);
        }
 
        publicKeyFilename = args[0].trim();
        inputData = args[1].trim();
        Encryption.encrypt(publicKeyFilename, inputData);
 
    }
 
    private String encryptA (String publicKeyFilename, String inputFilename, String encryptedFilename){
 
        try {
 
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
            String key = publicKeyFilename;
            AsymmetricKeyParameter publicKey = 
                (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.getDecoder().decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);
 
            String inputdata =inputFilename;
            byte[] messageBytes = inputdata.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
 
            System.out.println(getHexString(hexEncodedCipher));
            return Base64.getEncoder().encodeToString(hexEncodedCipher);
        }
        catch (Exception e) {
            System.out.println(e);
        }
		return null;
    }
    */
    public static String encrypt (String publicKeyFilename, String inputData){
 
        String encryptedData = null;
        try {
 
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
            String key = publicKeyFilename;
            AsymmetricKeyParameter publicKey = 
                (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.getDecoder().decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);
 
            byte[] messageBytes = inputData.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
 
            System.out.println(Base64.getDecoder().decode(key));
            encryptedData = Base64.getEncoder().encodeToString(hexEncodedCipher);

    
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return encryptedData;
    }
 
    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
 
    @POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)	
	public Response main(@FormParam ("Key")String keyString,
						 @FormParam ("Text")String input) {
    	
        String Result=Encryption.encrypt(keyString, input);
		String Message = "{\"Encrypted String\": \""+Result+"\"}";

        return Response
	  	          .status(Response.Status.OK)
	  	          .entity(Message)
	  	          .type(MediaType.APPLICATION_JSON)
	  	          .build();	    	
}
    
    
    @GET
    public Response resp() {
        GenerateKeys generateKeys = new GenerateKeys();
        String pubKey = null;
        String privKey = null;
 
        generateKeys.generate(pubKey,privKey);

        String message = "{\"Public Key\": \""+generateKeys.puKey+"\",\"Private Key\":\""+generateKeys.prKey+"\"}";
        
        return Response
          .status(Response.Status.OK)
          .entity(message)
          .type(MediaType.APPLICATION_JSON)
          .build();	    	
    }

 /*   private static String readFileAsString(String filePath)
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
}
