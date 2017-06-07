package data;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import tools.Crypto;
import tools.Printer;

public class ElectionKey {
	public ECPoint Y;
	public final List<ECPoint> tellers;

	public ElectionKey(JsonObject json) {
		Y = Crypto.curve.getCurve().decodePoint(Printer.hexToBytes(json.get("Y").getAsString()));

		tellers = new ArrayList<>();
		JsonArray L_json = json.get("tellers").getAsJsonArray();
		for (JsonElement item : L_json)
			tellers.add(Crypto.curve.getCurve().decodePoint(Printer.hexToBytes(item.getAsString())));
	}

	public ElectionKey() {
		tellers = new ArrayList<>();
		Y = Crypto.curve.getCurve().getInfinity();
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();

		json.addProperty("Y", Printer.bytesToHex(Y.getEncoded(true)));

		JsonArray tellers_json = new JsonArray();
		for (ECPoint item : tellers)
			tellers_json.add(new JsonPrimitive(Printer.bytesToHex(item.getEncoded(true))));
		json.add("tellers", tellers_json);

		return json;
	}

	public boolean addPublicKey(ECPoint y) {
		if (!tellers.contains(y)) {
			tellers.add(y);
			Y = Y.add(y).normalize();
			return true;
		} else
			return false;
	}
}
