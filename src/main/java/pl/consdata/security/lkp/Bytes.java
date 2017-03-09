package pl.consdata.security.lkp;

import java.nio.charset.StandardCharsets;

import org.abstractj.kalium.encoders.Hex;

/**
 * Utility class for presentation purposes.
 */
class Bytes {

	static byte[] fromString(String utf8String) {
		return utf8String.getBytes(StandardCharsets.UTF_8);
	}

	static String toUtf8String(byte[] rawBytes) {
		return new String(rawBytes, StandardCharsets.UTF_8);
	}

	static String toHexString(byte[] rawBytes) {
		return Hex.HEX.encode(rawBytes);
	}

}
