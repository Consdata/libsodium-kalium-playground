package pl.consdata.security.lkp;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.crypto.Password;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.encoders.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordHashing {

	/**
	 * Goal: generate password hash that can be stored in database. Hashing method should make brute-force
	 * attacks difficult and resource-intensive.
	 */
	public static void main(String[] args) {
		// kalium has only scrypt support - see https://github.com/abstractj/kalium/issues/69

		// opslimit represents a maximum amount of computations to perform. Raising this number will make the
		// function require more CPU cycles to compute a key.
		int opsLimit = NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE;
		// memlimit is the maximum amount of RAM that the function will use, in bytes. It is highly
		// recommended to allow the function to use at least 16 megabytes.
		int memLimit = NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE;
		byte[] randomSalt = new Random().randomBytes();

		String secretPassword = "MyS3cretPa$$";
		String hashedPassword =
				new Password().hash(Bytes.fromString(secretPassword), Encoder.HEX, randomSalt, opsLimit, memLimit);
		logger.info("secretPassword='{}' -> '{}'", secretPassword, hashedPassword);
	}

	private static Logger logger = LoggerFactory.getLogger(PasswordHashing.class.getSimpleName());

}
