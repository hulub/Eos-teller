package data;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import tools.Crypto;

public class Candidate {
	public final String name;
	public final BigInteger q;
	public final ECPoint v;
	
	public Candidate(String name) {
		this.name = name;
		q = Crypto.hash(this.name);
		v = Crypto.curve.getG().multiply(q).normalize();
	}
}
