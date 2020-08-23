package com.security.encryption.Test_EncryptDecrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

@Path("/stringapi")
public class StringApi {
	String key=null;
	String input=null;
	int mode=99;
	
	//Iv for BlockCiper Operations
	byte[] iv=new byte[16];
	
	public StringApi() {}
	
	  //String Encryption Method
	   public String encryptString(String keyBytes,String plaintext) {
		   String encryptedInput=null;
			try {
				   byte[] bouncykeyBytes= keyBytes.getBytes(StandardCharsets.UTF_8);//Converting String KEY into Bytes for further process
				   
				   //Cipher setup
				   AESEngine engine = new AESEngine();// AES engine applys Bouncy castles implementaion of Aes based Algorithm
				   CBCBlockCipher blockCipher = new CBCBlockCipher(engine);//-----CBC mode
				   PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default Padding scheme is PKCS5/PKCS7
				   
				   //Assigning Key for the cipher operations
				   KeyParameter keyParam = new KeyParameter(bouncykeyBytes);
				   CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
				   
				   byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8); //----User data
				   
				   cipher.init(true, keyParamWithIV);//--------cipher initialisation
				   byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
				   int length = cipher.processBytes(inputBytes,0,inputBytes.length,outputBytes, 0);//Enncrypt the inputBytes
				   cipher.doFinal(outputBytes, length);//---Last black processing
				   
				   encryptedInput = new String(Base64.getEncoder().encode(outputBytes));//Encoding output bytes into a Base64 String
				   //Above Conversion is required
				   //Reason:Lots of illegal characters generated 
				   
				   cipher.reset();
			} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
				e.printStackTrace();
				return "Encryption Failed Please Try Again";
			} //Do the final block
			return encryptedInput;
	   }
	   
	   //String Decryption Method
	   public String decryptString(String keyBytes,String encryptedText) {
		   		String decryptedText=null;
		   		int final_length;
				try {
					byte[] bouncykeyBytes= keyBytes.getBytes();
					AESEngine engine = new AESEngine();
					CBCBlockCipher blockCipher = new CBCBlockCipher(engine); 
					PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
					KeyParameter keyParam = new KeyParameter(bouncykeyBytes);
					CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
					
					byte[] inputBytes = Base64.getDecoder().decode(encryptedText);//Decoding the input string from Base64 to UTF8
			   		cipher.init(false, keyParamWithIV);//-----Decryption Mode
			   		byte[] comparisonBytes = new byte[cipher.getOutputSize(inputBytes.length)];
			   		int length = cipher.processBytes(inputBytes,0,inputBytes.length, comparisonBytes, 0);
					final_length = cipher.doFinal(comparisonBytes,length);
					
					decryptedText = new String(comparisonBytes,0,length+final_length,StandardCharsets.UTF_8);
				} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
					e.printStackTrace();
					return "Decryption Failed Please Try Again";
				}
		   		return decryptedText;
	   }
	   public Response responseMessage(String msg) {
	    	String message = "{\"Error\": \""+msg+"\"}";
	        return Response
	          .status(Response.Status.OK)
	          .entity(message)
	          .type(MediaType.APPLICATION_JSON)
	          .build();
	    }
	    @POST
		@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
		@Produces(MediaType.APPLICATION_JSON)	
		public Response main(@FormParam ("Pass")String keyString,
							 @FormParam ("text")String input,
							 @FormParam ("Mode") int mode1) {
	    	
				String finalKey=null;
				String Result=null;
				String Message = null;

				//Manual Padding of password
				char ch= '*';
				if(keyString.length() <= 32 && keyString.length()>0) { 
					finalKey = StringUtils.rightPad(keyString,32, ch);
				}else if(keyString.length()>32) { 
					finalKey = keyString.substring(0, Math.min(keyString.length(), 32));
				}else {
					Message = "Key Not found Please Try Again";
					return responseMessage(Message);
				}
				
				StringApi obj = new StringApi();
				//Mode select for Encryption and Decryption
				
				if(mode1==1){
					Result= obj.encryptString(finalKey,input);
					if(input==null) {
						return responseMessage("Please Enter text to ENCRYPT");
					}
					else {
					Message = "{\"Encrypted String\": \""+Result+"\"}";
					}
				}else if(mode1==2) {
					Result= obj.decryptString(finalKey,input);
					if(input==null) {
						responseMessage("Please Enter text to DECRYPT");
					}
					else {
					Message = "{\"Decrypted String\": \""+Result+"\"}";
					}
				}else {
					System.out.println("Invalid Mode Value");
					Message = "{\"Invalid Mode\": \"Please Check the Mode Value (1-Encryption/2-Decryption)\"}";
					}
				
				System.out.println(Result);
				//Response form the api
		        return Response
		  	          .status(Response.Status.OK)
		  	          .entity(Message)
		  	          .type(MediaType.APPLICATION_JSON)
		  	          .build();	    	

	    }


	    //Default Get response
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
}
