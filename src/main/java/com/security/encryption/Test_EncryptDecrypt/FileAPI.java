package com.security.encryption.Test_EncryptDecrypt;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
@Path("/Bouncy_File")
public class FileAPI {

    PaddedBufferedBlockCipher encryptCipher;
    PaddedBufferedBlockCipher decryptCipher;

    byte[] buf = new byte[32];              //input buffer
    byte[] obuf = new byte[512];            //output buffer

    byte[] key = null;

    public FileAPI(){
        key = "Default_Password".getBytes();
        InitCiphers();
    }
    public FileAPI(byte[] keyBytes){
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0 , key, 0, keyBytes.length);
        InitCiphers();
    }

    private void InitCiphers(){
        encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher =  new PaddedBufferedBlockCipher(new AESEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }

    public void ResetCiphers() {
        if(encryptCipher!=null)
            encryptCipher.reset();
        if(decryptCipher!=null)
            decryptCipher.reset();
    }

    public void encrypt(InputStream in, OutputStream out)
    throws ShortBufferException, IllegalBlockSizeException,  BadPaddingException,
            DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        try {
            int noBytesRead = 0;        
            int noBytesProcessed = 0;  

            while ((noBytesRead = in.read(buf)) >= 0) {
               noBytesProcessed = encryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
               out.write(obuf, 0, noBytesProcessed);
           }
            noBytesProcessed = encryptCipher.doFinal(obuf, 0);
            out.write(obuf, 0, noBytesProcessed);
            out.flush();
        }
        catch (java.io.IOException e) {
            System.out.println(e.getMessage());
        }
    }
    public Response responseMessage(String msg) {
    	String message = "{\"Error\": \""+msg+"\"}";
        return Response
          .status(Response.Status.OK)
          .entity(message)
          .type(MediaType.APPLICATION_JSON)
          .build();
    }
    public void decrypt(InputStream in, OutputStream out)
    throws ShortBufferException, IllegalBlockSizeException,  BadPaddingException,
            DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        try {
            int noBytesRead = 0;        
            int noBytesProcessed = 0;   

            while ((noBytesRead = in.read(buf)) >= 0) {
                    noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
                    out.write(obuf, 0, noBytesProcessed);
            }
            noBytesProcessed = decryptCipher.doFinal(obuf, 0);
            out.write(obuf, 0, noBytesProcessed);

            out.flush();
        }
        catch (java.io.IOException e) {
             System.out.println(e.getMessage());
        }
    }
    @POST
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.MULTIPART_FORM_DATA)
	public static Response main(
			@FormDataParam("Pass") String key,
			@FormDataParam("Mode") int mode,
			@FormDataParam("file") InputStream uploadedInputStream,  
            @FormDataParam("file") FormDataContentDisposition fileDetail){
    	
    		String finalKey = null;
    		String ext = FilenameUtils.getExtension(fileDetail.getFileName());
    		
    		char ch= '*';
			if(key.length() <= 32) { 
				finalKey = StringUtils.rightPad(key,32, ch);
			}else if(key.length()>32) { 
				finalKey = key.substring(0, Math.min(key.length(), 32));
			}else {System.out.println("Key not found");}
			
			FileAPI cipher = new FileAPI(finalKey.getBytes(StandardCharsets.UTF_8));
			//String fileLoc="C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\"+fileDetail;

           try {
        	   FileOutputStream outputStream = new FileOutputStream(new File(fileDetail.getFileName()));
        	   if(mode==0) {
        		   cipher.encrypt(uploadedInputStream, outputStream);
        	   			}else if(mode==1) {
        	        		   cipher.decrypt(uploadedInputStream, outputStream);
        	   			}else {
        	   				System.out.println("Invlaid Mode Selected");
        	   			}
        	   
				 	File EncryptedFile = new File(fileDetail.getFileName());
	                ResponseBuilder response = Response.ok((Object) EncryptedFile);  
	                response.header("Content-Disposition","attachment; filename=\"Output_File."+ext+"\"");  
	                return response.build();
	                
			} catch (DataLengthException | ShortBufferException | IllegalBlockSizeException | BadPaddingException
					| IllegalStateException | InvalidCipherTextException | FileNotFoundException e) {
				e.printStackTrace();
				cipher.responseMessage("Process Failed Please Try Again");			
			}
		return null;
	       }
}