package pl.consdata.security.lkp;

import org.abstractj.kalium.crypto.Hash;
import org.abstractj.kalium.encoders.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal: generate secure hash of a given message.
 */
public class GenericHashing {

	public static void main(String[] args) {
		final String message = "This is just an example";

		// kalium doesn't have a helper function for generic_hashing yet,
		// so we have to choose the method manually
		String sha256Hash = new Hash().sha256(message, Encoder.HEX);
		String sha512Hash = new Hash().sha512(message, Encoder.HEX);
		String blake2Hash = new Hash().blake2(message, Encoder.HEX);

		logger.info("Message SHA-256 hash: {}", sha256Hash);
		logger.info("Message SHA-512 hash: {}", sha512Hash);
		logger.info("Message Blake2 hash: {}", blake2Hash);
	}

	private static final Logger logger = LoggerFactory.getLogger(GenericHashing.class);

}
