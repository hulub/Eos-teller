package data;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonObject;

import tools.Crypto;
import tools.Printer;

public class DLEPK {
	public final ECPoint commitment1, commitment2;
	public final BigInteger challenge;
	public final BigInteger response;
	
	public DLEPK(ECPoint commitment1, ECPoint commitment2, BigInteger challenge, BigInteger response) {
		this.commitment1 = commitment1;
		this.commitment2 = commitment2;
		this.challenge = challenge;
		this.response = response;
	}

	public DLEPK(JsonObject json) {
		commitment1 = Crypto.curve.getCurve().decodePoint(Printer.hexToBytes(json.get("commitment1").getAsString()));
		commitment2 = Crypto.curve.getCurve().decodePoint(Printer.hexToBytes(json.get("commitment2").getAsString()));
		challenge = new BigInteger(1, Printer.hexToBytes(json.get("challenge").getAsString()));
		response = new BigInteger(1, Printer.hexToBytes(json.get("response").getAsString()));
	}

	/**
	 * Verify this discrete logarithm equality proof between log_G1 (Y1) = log_G2 (Y2).
	 * Returns true if 
	 * 		- the equality holds
	 * 		- challenge = hash(G1, G2, commitment1, commitment2)
	 * Returns false otherwise
	 * @param G1, G2
	 * @param Y1, Y2
	 * @return a boolean for either the check passed or failed
	 */
	public boolean check(ECPoint G1, ECPoint G2, ECPoint Y1, ECPoint Y2) {
		return checkWithoutChallenge(G1, G2, Y1, Y2)
				&& challenge.equals(Crypto.hash(Arrays.asList(G1, G2, commitment1, commitment2)));
	}

	/**
	 * Verify this discrete logarithm equality proof between log_G1 (Y1) = log_G2 (Y2).
	 * It does not check the challenge computation. 
	 * Returns true if 
	 * 		- the equality holds
	 * Returns false otherwise
	 * @param G1, G2
	 * @param Y1, Y2
	 * @return a boolean for either the check passed or failed
	 */
	public boolean checkWithoutChallenge(ECPoint G1, ECPoint G2, ECPoint Y1, ECPoint Y2) {
		if (!G1.multiply(response).normalize().equals(commitment1.add(Y1.multiply(challenge)).normalize()))
			return false;
		if (!G2.multiply(response).normalize().equals(commitment2.add(Y2.multiply(challenge)).normalize()))
			return false;

		return true;
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();

		json.addProperty("commitment1", Printer.bytesToHex(commitment1.getEncoded(true)));
		json.addProperty("commitment2", Printer.bytesToHex(commitment2.getEncoded(true)));
		json.addProperty("challenge", Printer.bytesToHex(challenge.toByteArray()));
		json.addProperty("response", Printer.bytesToHex(response.toByteArray()));

		return json;
	}
}
