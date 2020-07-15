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

import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.*;
import java.util.zip.*;

@Path("/filesDecrypt")  

public class DecryptFile {
	@POST
    @Path("/upload")
	@Produces("text/plain")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
	public static Response main(
			@FormDataParam("Pass") String key,
			@FormDataParam("file") InputStream uploadedInputStream,  
            @FormDataParam("file") FormDataContentDisposition fileDetail) {
		String zipPath="C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\EncryptedText.zip";
		//String dest = "C:\\Users\\admin\\git\\Encryption\\encryption\\Upload";	
		String folderPath = "C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Upload\\File Decryption";
		unzip(zipPath,folderPath);
		String password = key;
		
		File file = new File(folderPath);
     	if (!file.exists()) {
    		if (file.mkdir()) {}
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
			fos = new FileOutputStream("C:\\Users\\admin\\git\\Encryption\\Test-EncryptDecrypt\\Result\\plainfile_decrypted.txt");
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
		
/*
     	 File file = new File("C:\\Users\\admin\\Desktop\\salt.enc");
	 File file2 = new File("C:\\Users\\admin\\Desktop\\iv.enc");
	 File file3 = new File("C:\\Users\\admin\\Desktop\\encryptedfile.txt");
	           
        if(file.delete()&&file2.delete()&&file3.delete()) 
        {} 
        else
        { 
        System.out.println("Please ignore/delete the salt.enc or iv.enc file"); 
        }    */
		
   
     	}
    String output1 = "File successfully uploaded please Wait for the download to begin"; 
    return Response.status(200).entity(output1).build();	
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