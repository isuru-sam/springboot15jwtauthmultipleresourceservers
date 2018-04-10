package com.oauthauthorizationserver.config;

import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Based on
 * http://www.java2s.com/Code/Java/Security/RetrievingaKeyPairfromaKeyStore.htm
 */
@Component
public class SecretKeyProvider {

	public String getKey() throws URISyntaxException, KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {
		return new String(getKeyPair().getPublic().getEncoded(), "UTF-8");
	}

	public String getPrivateKey() throws URISyntaxException, KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {
		return new String(getKeyPair().getPrivate().getEncoded(), "UTF-8");
	}

	private KeyPair getKeyPair() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {
		FileInputStream is = new FileInputStream("isa.jks");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, "isaisa".toCharArray());

		String alias = "isa";

		Key key = keystore.getKey(alias, "isaisa".toCharArray());
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			Certificate cert = keystore.getCertificate(alias);

			// Get public key
			PublicKey publicKey = cert.getPublicKey();

			// Return a key pair
			return new KeyPair(publicKey, (PrivateKey) key);
		} else
			throw new UnrecoverableKeyException();
	}

}
