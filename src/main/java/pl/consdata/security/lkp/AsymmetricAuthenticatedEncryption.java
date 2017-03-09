package pl.consdata.security.lkp;

import static pl.consdata.security.lkp.Bytes.toHexString;
import static pl.consdata.security.lkp.Bytes.toUtf8String;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.crypto.Box;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.keys.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal: prepare a message encrypted with asymmetric cipher (with integrity control) for the chosen recipient,
 * and let him verify sender's identity.
 */
public class AsymmetricAuthenticatedEncryption {

	public static void main(String[] args) {
		// generate key pairs (public & private) for Bob and Alice
		KeyPair aliceKeys = new KeyPair(new Random().randomBytes());
		KeyPair bobKeys = new KeyPair(new Random().randomBytes());
		// create box object for each user - asymmetric encryption/decryption engine
		Box bobBox = new Box(aliceKeys.getPublicKey(), bobKeys.getPrivateKey());
		Box aliceBox = new Box(bobKeys.getPublicKey(), aliceKeys.getPrivateKey());

		// Alice sends secret message to Bob
		byte[] aliceMsgNonce = new Random().randomBytes(NONCE_BYTES_SIZE);
		final String messageToBob = "Hi Bob!";
		logOriginalMessage("Alice", messageToBob);

		byte[] encryptedMessageToBob = aliceBox.encrypt(aliceMsgNonce, Bytes.fromString(messageToBob));
		logEncryptedMessage("Alice", encryptedMessageToBob);
		// Bob decrypts the message
		byte[] decryptedMessageFromAlice = bobBox.decrypt(aliceMsgNonce, encryptedMessageToBob);
		logDecryptedMessage("Alice", decryptedMessageFromAlice);

		// Bob responds with secret message for Alice
		byte[] bobMsgNonce = new Random().randomBytes(NONCE_BYTES_SIZE);
		final String messageToAlice = "Hello Alice!";
		logOriginalMessage("Bob", messageToAlice);
		byte[] encryptedMessageToAlice = bobBox.encrypt(bobMsgNonce, Bytes.fromString(messageToAlice));
		logEncryptedMessage("Bob", encryptedMessageToAlice);
		// Alice decrypts the message
		byte[] decryptedMessageFromBob = bobBox.decrypt(bobMsgNonce, encryptedMessageToAlice);
		logDecryptedMessage("Bob", decryptedMessageFromBob);
	}

	private static void logOriginalMessage(String sender, String message) {
		logger.info("Original message from {}: '{}'", sender, message);
		logger.debug("Original message from {} (hex): '{}'", sender, toHexString(message.getBytes()));
	}

	private static void logEncryptedMessage(String sender, byte[] encryptedMessage) {
		logger.debug("Encrypted message from {} (hex): '{}'", sender, toHexString(encryptedMessage));
	}

	private static void logDecryptedMessage(String sender, byte[] decryptedMessage) {
		logger.info("Decrypted message from {}: '{}'", sender, toUtf8String(decryptedMessage));
	}

	private static final Logger logger = LoggerFactory.getLogger(AsymmetricAuthenticatedEncryption.class);

	private static final int NONCE_BYTES_SIZE = NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES;

}
