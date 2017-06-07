package main;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonObject;

import data.Ballot;
import data.DLEPK;
import data.PartialDecryption;
import data.Vote;
import tools.Crypto;
import tools.Printer;

public class Teller {
	private final BigInteger x;
	public final ECPoint y;
	private final Random random;

	public Teller(JsonObject json) {
		this(new BigInteger(1, Printer.hexToBytes(json.get("x").getAsString())));
	}

	public Teller(BigInteger x) {
		this.x = x.mod(Crypto.curve.getN());
		y = Crypto.curve.getG().multiply(this.x).normalize();
		random = new SecureRandom();
	}

	protected BigInteger getPrivateKey() {
		return x;
	}

	/**
	 * Apply partial decryption on the vote.
	 * @param votes the vote board
	 */
	public void applyVotePartialDecryption(List<Vote> votes) {
		for (Vote v : votes) {
			ECPoint vote_S = v.vote_enc.R.multiply(x).normalize();
			DLEPK vote_pk = generateDLEProof(Crypto.curve.getG(), v.vote_enc.R, x);
			v.vote_part_dec.add(new PartialDecryption(vote_S, vote_pk));
		}
	}

	/**
	 * Apply partial decryption on the color and eID. In each ballot it appends its partial decryption.
	 * @param ballots the ballot board
	 */
	public void applyBallotPartialDecryption(List<Ballot> ballots) {
		for (Ballot b : ballots) {
			ECPoint color_S = b.color_enc.R.multiply(x).normalize();
			DLEPK color_pk = generateDLEProof(Crypto.curve.getG(), b.color_enc.R, x);
			b.color_part_dec.add(new PartialDecryption(color_S, color_pk));

			ECPoint eID_S = b.eID_enc.R.multiply(x).normalize();
			DLEPK eID_pk = generateDLEProof(Crypto.curve.getG(), b.eID_enc.R, x);
			b.eID_part_dec.add(new PartialDecryption(eID_S, eID_pk));
		}
	}

	private DLEPK generateDLEProof(ECPoint G1, ECPoint G2, BigInteger x) {
		BigInteger k = new BigInteger(256, random).mod(Crypto.curve.getN());
		ECPoint commitment1 = G1.multiply(k).normalize();
		ECPoint commitment2 = G2.multiply(k).normalize();

		BigInteger challenge = Crypto.hash(Arrays.asList(G1, G2, commitment1, commitment2));

		BigInteger response = k.add(challenge.multiply(x)).mod(Crypto.curve.getN());

		return new DLEPK(commitment1, commitment2, challenge, response);
	}
}
