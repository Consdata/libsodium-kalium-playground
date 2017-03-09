package pl.consdata.security.lkp;

import static pl.consdata.security.lkp.Bytes.toHexString;
import static pl.consdata.security.lkp.Bytes.toUtf8String;

import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.crypto.SealedBox;
import org.abstractj.kalium.keys.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal: prepare a message encrypted with asymmetric cipher (with integrity control) for the chosen recipient,
 * but keep the sender anonymous.
 */
public class AnonymousAsymmetricEncryption {

	public static void main(String[] args) {
		// Alice's (recipient's) public & private key pair
		KeyPair aliceKeys = new KeyPair(new Random().randomBytes());

		// to encrypt anonymous message whe need only Alice's public key
		SealedBox anonymousSealedBox = new SealedBox(aliceKeys.getPublicKey().toBytes());

		final String anonymousMessage = "Hello Alice! Catch me if you can!";
		logger.info("Original message: '{}'", anonymousMessage);
		logger.debug("Original message (hex): '{}'", toHexString(anonymousMessage.getBytes()));

		byte[] anonymousEncryptedMessage = anonymousSealedBox.encrypt(Bytes.fromString(anonymousMessage));
		logger.debug("Encrypted message (hex): {}", toHexString(anonymousEncryptedMessage));

		// only Alice knows both her private & public key which are required to decrypt a message
		SealedBox aliceSealedBox =
				new SealedBox(aliceKeys.getPublicKey().toBytes(), aliceKeys.getPrivateKey().toBytes());
		byte[] decryptedMessage = aliceSealedBox.decrypt(anonymousEncryptedMessage);
		logger.info("Decrypted message: '{}'", toUtf8String(decryptedMessage));
	}

	private static final Logger logger = LoggerFactory.getLogger(AnonymousAsymmetricEncryption.class);

}
