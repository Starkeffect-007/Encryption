package com.security.encryption.Test_EncryptDecrypt;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.*;
import java.util.zip.*;

@Path("/filesDecrypt")  

public class FileDecryptionTest {
	@POST
    @Path("/upload")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.MULTIPART_FORM_DATA)
	public static Response main(
			@FormDataParam("Pass") String key,
			@FormDataParam("file") InputStream uploadedInputStream,  
            @FormDataParam("file") FormDataContentDisposition fileDetail){
		String zipPath="C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\EncryptedText.zip";
		String dest = "C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption";	
		unzip(zipPath,dest);
		String password = key;
		
		FileInputStream saltFis = null;
		try {
			saltFis = new FileInputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption\\salt.enc");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] salt = new byte[8];
		try {
			saltFis.read(salt);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			saltFis.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		FileInputStream ivFis = null;
		try {
			ivFis = new FileInputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption\\iv.enc");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] iv = new byte[16];
		try {
			ivFis.read(iv);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			ivFis.close();
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
		SecretKey tmp = null;
		try {
			tmp = factory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		FileInputStream fis = null;
		try {
			fis = new FileInputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption\\encryptedfile.txt");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\plainfiledecrypted.txt");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte[] in = new byte[64];
		int read;

		try {
			while ((read = fis.read(in)) != -1) {
				byte[] output = cipher.update(in, 0, read);
				if (output != null)
					fos.write(output);
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
				fos.write(output);
				fis.close();
				fos.flush();
				fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		System.out.println("File Decrypted.");

		File index = new File("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption");
		String[]entries = index.list();
		for(String s: entries){
		    File currentFile = new File(index.getPath(),s);
		    currentFile.delete();
		}
	    index.delete();

		//String output1 = "File successfully uploaded please Wait for the download to begin"; 
        //return Response.status(200).entity(output1).build();   
        
        File Decryptedfile = new File("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\plainfiledecrypted.txt");  
        ResponseBuilder response = Response.ok((Object) Decryptedfile);  
        response.header("Content-Disposition","attachment; filename=\"plainfile_decrypted.txt\"");  
        return response.build();
}
private static void unzip(String zipFilePath, String destDir) {
        File dir = new File(destDir);
        if(!dir.exists()) dir.mkdirs();
        FileInputStream fis;

        byte[] buffer = new byte[1024];
        try {
            fis = new FileInputStream(zipFilePath);
            ZipInputStream zis = new ZipInputStream(fis);
            ZipEntry ze = zis.getNextEntry();
            while(ze != null){
                String fileName = ze.getName();
                File newFile = new File(destDir + File.separator + fileName);
                System.out.println("Unzipping");
                //create directories for sub directories in zip
                new File(newFile.getParent()).mkdirs();
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
                }
                fos.close();
                zis.closeEntry();
                ze = zis.getNextEntry();
            }
           
            zis.closeEntry();
            zis.close();
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
      }  

}    