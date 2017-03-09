package pl.consdata.security.lkp;

import static java.nio.charset.StandardCharsets.UTF_8;
import static pl.consdata.security.lkp.Bytes.toHexString;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.crypto.SecretBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal: encrypt message with symmetric cipher (with integrity control) using given secret key.
 */
public class SymmetricAuthenticatedEncryption {

	public static void main(String[] args) {
		final String secretMessage = "This is a very secret message!";
		logOriginalMessage(secretMessage);

		// parameters
		byte[] secretKey = new Random().randomBytes();
		byte[] nonce = new Random().randomBytes(NONCE_BYTES_LENGTH);

		// secret box - encryption/decryption engine
		SecretBox secretBox = new SecretBox(secretKey);

		// encryption
		byte[] encryptedBytes = secretBox.encrypt(nonce, secretMessage.getBytes(UTF_8));
		logger.debug("Encrypted string (hex): '{}'", toHexString(encryptedBytes));

		// decryption
		byte[] decryptedBytes = secretBox.decrypt(nonce, encryptedBytes);
		logger.info("Decrypted string: '{}'", new String(decryptedBytes, UTF_8));
	}

	private static void logOriginalMessage(String secretMessage) {
		logger.info("Original message: '{}'", secretMessage);
		logger.debug("Original message (hex): '{}'", toHexString(secretMessage.getBytes()));
	}

	private static final Logger logger = LoggerFactory.getLogger(SymmetricAuthenticatedEncryption.class);

	private static final int NONCE_BYTES_LENGTH = NaCl.Sodium.CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES;

}
