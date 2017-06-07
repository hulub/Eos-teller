package data;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonObject;

import tools.Crypto;
import tools.Printer;

public class PartialDecryption {
	public final ECPoint S;
	public final DLEPK pk;
	
	public PartialDecryption(ECPoint S, DLEPK pk) {
		this.S = S;
		this.pk = pk;
	}

	public PartialDecryption(JsonObject json) {
		S = Crypto.curve.getCurve().decodePoint(Printer.hexToBytes(json.get("S").getAsString()));
		pk = new DLEPK(json.get("pk").getAsJsonObject());
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();
		
		json.addProperty("S", Printer.bytesToHex(S.getEncoded(true)));
		json.add("pk", pk.toJsonObject());
		
		return json;
	}
}
