package com.security.encryption.Test_EncryptDecrypt;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.*;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import java.io.*;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

@Path("/filesEncrypt")  

public class EncryptFile {
	
	@POST
    @Path("/upload")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.MULTIPART_FORM_DATA)
	public static Response main(
			@FormDataParam("Pass") String key,
			@FormDataParam("file") InputStream uploadedInputStream,  
            @FormDataParam("file") FormDataContentDisposition fileDetail){
		String fName=fileDetail.getFileName();
		String fileLocation = "C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\" + fileDetail.getFileName();  
        //saving file  
try {  
    FileOutputStream out = new FileOutputStream(new File(fileLocation));  
    int read = 0;  
    byte[] bytes = new byte[1024];  
    out = new FileOutputStream(new File(fileLocation));  
    while ((read = uploadedInputStream.read(bytes)) != -1) {  
        out.write(bytes, 0, read);  
    }  
    out.flush();  
    out.close();  
} catch (IOException e) {e.printStackTrace();}
		
		FileInputStream inpFile = null;
		try {
			inpFile = new FileInputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\"+fName);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		String folderPath = "C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Encryption";
		String zipPath = "C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\EncryptedText.zip";
      		File file = new File(folderPath);
             	if (!file.exists()) {
            		if (file.mkdir()) {
        System.out.println("Directory is created!");
		FileOutputStream outFile = null;
		try {
			outFile = new FileOutputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Encryption\\encryptedfile.txt");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}


		String password = key;

		byte[] salt = new byte[8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(salt);
		FileOutputStream saltOutFile = null;
		try {
			saltOutFile = new FileOutputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Encryption\\salt.enc");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		try {
			saltOutFile.write(salt);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			saltOutFile.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		SecretKeyFactory factory = null;
		try {
			factory = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 512,
				256);
		SecretKey secretKey = null;
		try {
			secretKey = factory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secret);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		AlgorithmParameters params = cipher.getParameters();

		FileOutputStream ivOutFile = null;
		try {
			ivOutFile = new FileOutputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Encryption\\iv.enc");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] iv = null;
		try {
			iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			ivOutFile.write(iv);
			ivOutFile.close();
		} catch (InvalidParameterSpecException | IOException e) {
			e.printStackTrace();
		}
		
		byte[] input = new byte[64];
		int bytesRead;

		try {
			while ((bytesRead = inpFile.read(input)) != -1) {
				byte[] output = cipher.update(input, 0, bytesRead);
				if (output != null)
					outFile.write(output);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] output = null;
		try {
			output = cipher.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		if (output != null)
			try {
				outFile.write(output);
			} catch (IOException e) {
				e.printStackTrace();
			}
		try {
			inpFile.close();
			outFile.flush();
			outFile.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("File Encrypted.");
		File index = new File("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Encryption");
		 //File file2 = new File("C:\\Users\\admin\\Desktop\\iv.enc");
		 //File file3 = new File("C:\\Users\\admin\\Desktop\\encryptedfile.txt");
		           		
		ZipFiles zipUtil = new ZipFiles();
		try {
	        zipUtil.zipDirectory(index, zipPath);
	        String[]entries = index.list();
			for(String s: entries){
			    File currentFile = new File(index.getPath(),s);
			    currentFile.delete();
			}
		    index.delete();

			} catch (Exception ex) {
			ex.printStackTrace();
			}
	}
            	} else {
               			System.out.println("Failed to create directory!");
       					 }
             	//String output = "File successfully uploaded please Wait for the download to begin"; 
               // return Response.status(200).entity(output).build();
                
             	File Encryptedfile = new File("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\EncryptedText.zip");  
                ResponseBuilder response = Response.ok((Object) Encryptedfile);  
                response.header("Content-Disposition","attachment; filename=\"EncryptedText.zip\"");  
                return response.build();
                
                }	
}