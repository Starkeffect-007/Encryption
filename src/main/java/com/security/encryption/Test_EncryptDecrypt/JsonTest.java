package com.security.encryption.Test_EncryptDecrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

@Path("/JsonTest")
public class JsonTest {
	byte[] key=null;
	String input=null;
	int mode,algorithm;
	byte[] iv=new byte[16];
    PaddedBufferedBlockCipher encryptCipher;
    PaddedBufferedBlockCipher decryptCipher;

    private void InitCiphers(int algorithm){
    	KeyParameter keyParam = new KeyParameter(key);
		ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv);

    	if(algorithm==1) {
    		encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
            encryptCipher.init(true, keyParam);
            decryptCipher =  new PaddedBufferedBlockCipher(new AESEngine());
            decryptCipher.init(false,keyParam);
    	}else if(algorithm==2){
    		encryptCipher = new PaddedBufferedBlockCipher(new TwofishEngine());
            encryptCipher.init(true,keyParam);
            decryptCipher =  new PaddedBufferedBlockCipher(new TwofishEngine());
            decryptCipher.init(false,keyParam);
    	}else if(algorithm==3){
    		encryptCipher = new PaddedBufferedBlockCipher(new CAST6Engine());
            encryptCipher.init(true,keyParam);
            decryptCipher =  new PaddedBufferedBlockCipher(new CAST6Engine());
            decryptCipher.init(false,keyParam);
    	}else {} 
    }
    
    public void ResetCiphers() {
        if(encryptCipher!=null)
            encryptCipher.reset();
        if(decryptCipher!=null)
            decryptCipher.reset();
    }
    
    public JsonTest() {
        key = "Default_Password".getBytes();
        algorithm=0;
        InitCiphers(algorithm);
    }
    
	public JsonTest(byte[] keyBytes,int Algorithm) {
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0 , key, 0, keyBytes.length);
		InitCiphers(Algorithm);
	}
	
	   public String encryptString(String plaintext) {
		   String encryptedInput=null;
			try {  
				   byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8);
				   //encryptCipher.init(true, keyParamWithIV);
				   byte[] outputBytes = new byte[encryptCipher.getOutputSize(inputBytes.length)];
				   int length = encryptCipher.processBytes(inputBytes,0,inputBytes.length,outputBytes, 0);
				   encryptCipher.doFinal(outputBytes, length);
				   encryptedInput = new String(Base64.getEncoder().encode(outputBytes));
				   encryptCipher.reset();
			} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //Do the final block
			return encryptedInput;
	   }
	   public String decryptString(String encryptedText) {
		   		String decryptedText=null;
		   		int final_length;
				try {
					byte[] inputBytes = Base64.getDecoder().decode(encryptedText);
					//decryptCipher.init(false, keyParamWithIV);
			   		byte[] comparisonBytes = new byte[decryptCipher.getOutputSize(inputBytes.length)];
			   		int length = decryptCipher.processBytes(inputBytes,0,inputBytes.length, comparisonBytes, 0);
					final_length = decryptCipher.doFinal(comparisonBytes,length);
					decryptedText = new String(comparisonBytes,0,length+final_length,StandardCharsets.UTF_8);
				} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		   		return decryptedText;
	   }
	   
	    @POST
		@Consumes(MediaType.APPLICATION_JSON)
		@Produces(MediaType.APPLICATION_JSON)	
		public Response main(RequestBody inputjsonObj) {
	    	
	    		String keyString = inputjsonObj.Pass;
	    		String input= inputjsonObj.Text;
	    		int mode1 = inputjsonObj.Mode;
	    		int algo= inputjsonObj.Alg;
	    		
				String finalKey=null;
				String Result=null;
				char ch= '*';
				if(keyString.length() <= 32) {
					finalKey = StringUtils.rightPad(keyString,32, ch);
				}else if(keyString.length()>32) {
					finalKey = keyString.substring(0, Math.min(keyString.length(), 32));
					}
				else {System.out.println("Key not found");}
				System.out.println(finalKey);
				
				JsonTest obj = new JsonTest(finalKey.getBytes(),algo);
			
				String Message = null;
				if(mode1==1){
					Result = obj.encryptString(input);
					Message = "{\"Encrypted String\": \""+Result+"\"}";
				}else if(mode1==2) {
					Result = obj.decryptString(input);
					Message = "{\"Decrypted String\": \""+Result+"\"}";
				}else {
					Message = "{\"Invalid Mode\": \"Please Check the Mode Value (0-Encryption/1-Decryption)\"}";
					}
				
				  return Response
					      .status(Response.Status.OK)
					      .entity(Message)
					      .header("Access-Control-Allow-Origin", "*")
					      .type(MediaType.APPLICATION_JSON)
					      .build();
				  }
	    @GET
	    public Response resp() {
			String Msg = "{\"Error\": \"Method Not Found\"}";

	    	return Response
	    		      .status(Response.Status.OK)
	    		      .entity(Msg)
	    		      .type(MediaType.APPLICATION_JSON)
	    		      .build();	    	
	    }
}
