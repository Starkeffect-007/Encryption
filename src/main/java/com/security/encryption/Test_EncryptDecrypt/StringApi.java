package com.security.encryption.Test_EncryptDecrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
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
	int mode;
	byte[] iv=new byte[16];
	
	public StringApi() {   
	}
	  
	   public String encryptString(String keyBytes,String plaintext) {
		   String encryptedInput=null;
			try {
				   byte[] bouncykeyBytes= keyBytes.getBytes();
				   AESEngine engine = new AESEngine();
				   CBCBlockCipher blockCipher = new CBCBlockCipher(engine); //CBC
				   PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
				   KeyParameter keyParam = new KeyParameter(bouncykeyBytes);
				   CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
				   
				   byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8);
				   cipher.init(true, keyParamWithIV);
				   byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
				   int length = cipher.processBytes(inputBytes,0,inputBytes.length,outputBytes, 0);
				   cipher.doFinal(outputBytes, length);
				   encryptedInput = new String(Base64.getEncoder().encode(outputBytes));
				   cipher.reset();
			} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //Do the final block
			return encryptedInput;
	   }
	   public String decryptString(String keyBytes,String encryptedText) {
		   		String decryptedText=null;
		   		int final_length;
				try {
					byte[] bouncykeyBytes= keyBytes.getBytes();
					AESEngine engine = new AESEngine();
					CBCBlockCipher blockCipher = new CBCBlockCipher(engine); //CBC
					PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
					KeyParameter keyParam = new KeyParameter(bouncykeyBytes);
					CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
					
					byte[] inputBytes = Base64.getDecoder().decode(encryptedText);
			   		cipher.init(false, keyParamWithIV);
			   		byte[] comparisonBytes = new byte[cipher.getOutputSize(inputBytes.length)];
			   		int length = cipher.processBytes(inputBytes,0,inputBytes.length, comparisonBytes, 0);
					final_length = cipher.doFinal(comparisonBytes,length);
					System.out.println(final_length);
					//decryptedText = new String(comparisonBytes,0,final_length,StandardCharsets.UTF_8);
					decryptedText = new String(comparisonBytes,0,length+final_length,StandardCharsets.UTF_8);
				} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		   		return decryptedText;
	   }
	   
	    @POST
		@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
		@Produces(MediaType.APPLICATION_JSON)	
		public static String main(@FormParam ("Pass")String keyString,@FormParam ("Text")String input,@FormParam ("Mode") int mode1) {
				String finalKey=null;
				String Result=null;
				char ch= '*';
				if(keyString.length() <= 32) {
					finalKey = StringUtils.rightPad(keyString,32, ch);
				}else if(keyString.length()>32) {
					finalKey = keyString.substring(0, Math.min(keyString.length(), 10));
					}
				else {System.out.println("Key not found");}
				
				StringApi obj = new StringApi();
				
				if(mode1==0){
					Result= obj.encryptString(finalKey,input);
				}else if(mode1==1) {
					Result= obj.decryptString(finalKey,input);
				}else {
					System.out.println("Invalid Mode Value");
					}
				return Result;
			}


}
