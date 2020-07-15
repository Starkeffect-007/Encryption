package com.security.encryption.Test_EncryptDecrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
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
@Path("/p_decrypt")



public class decrypt
{
	@POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
	public String decryptString(@FormParam ("Pass")String keyString,@FormParam ("text")String input){
		
    byte[] inputBytes = null;
    String decryptedText=null;
    char ch ='*' ;
    String finalKey = StringUtils.rightPad(keyString,32, ch);
    inputBytes = Base64.getDecoder().decode(input);
    //inputBytes= input.getBytes(StandardCharsets.UTF_8);
    //inputBytes = DatatypeConverter.parseBase64Binary(input);
    byte[] bouncykey= finalKey.getBytes();
    byte[] iv = new byte[16];

    
    //Set up
    AESEngine engine = new AESEngine(); 
    CBCBlockCipher blockCipher = new CBCBlockCipher(engine); //CBC
    PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
    KeyParameter keyParam = new KeyParameter(bouncykey);
    CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);

    //Decrypt 
    try {
    	cipher.init(false, keyParamWithIV);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        int length = cipher.processBytes(inputBytes,0,inputBytes.length, comparisonBytes, 0);
		int final_length = cipher.doFinal(comparisonBytes,length);
		//byte[] decrypted = Base64.getEncoder().encode(comparisonBytes);
		decryptedText= new String(comparisonBytes,0,length+final_length,StandardCharsets.UTF_8);
	} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
		e.printStackTrace();
	}
    return decryptedText;
    }
   
}
