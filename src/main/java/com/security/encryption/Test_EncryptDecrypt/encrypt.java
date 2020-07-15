package com.security.encryption.Test_EncryptDecrypt;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

@Path("/p_encrypt")

public class encrypt {
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
	public String encryptString(@FormParam ("Pass")String keyString,@FormParam ("text")String input) {
    String encryptedInput = null;
	String decryptedText = null;

    byte[] inputBytes;
    
    char ch ='*' ;
    String finalKey = StringUtils.rightPad(keyString,32, ch);

    inputBytes = input.getBytes(StandardCharsets.UTF_8);
    byte[] bouncykey= finalKey.getBytes();
	byte[] iv = new byte[16];  

   //Set up
   AESEngine engine = new AESEngine();
   CBCBlockCipher blockCipher = new CBCBlockCipher(engine); //CBC
   PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
   KeyParameter keyParam;
   keyParam = new KeyParameter(bouncykey);
	CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
try {
	cipher.init(true, keyParamWithIV);
	byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
	int length = cipher.processBytes(inputBytes,0,inputBytes.length,outputBytes, 0);
	cipher.doFinal(outputBytes, length); //Do the final block
	//encryptedInput = DatatypeConverter.printBase64Binary(outputBytes);
	encryptedInput = new String(Base64.getEncoder().encode(outputBytes));
	//encryptedInput= new String(outputBytes,StandardCharsets.UTF_8);
	cipher.reset();
	
	//byte[] outBytes = DatatypeConverter.parseBase64Binary(encryptedInput);
	byte[] outBytes = Base64.getDecoder().decode(encryptedInput);
	cipher.init(false, keyParamWithIV);
    byte[] comparisonBytes = new byte[cipher.getOutputSize(outBytes.length)];
    int length1 = cipher.processBytes(outBytes,0,outBytes.length, comparisonBytes, 0);
	int final_length = cipher.doFinal(comparisonBytes,length1);
	//decryptedText = Base64.getEncoder().encodeToString(comparisonBytes);
	decryptedText = new String(comparisonBytes,0,final_length,StandardCharsets.UTF_8);
	System.out.println(decryptedText);
	System.out.println(final_length);

	
} catch (DataLengthException | IllegalStateException|InvalidCipherTextException e) {
	e.printStackTrace();
	}
return encryptedInput;
}
}
