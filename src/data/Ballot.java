package data;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import tools.Printer;

public class Ballot {
	public final ElGamalTuple color_enc, eID_enc, vote_enc;
	public List<PartialDecryption> color_part_dec, eID_part_dec;
	public boolean valid = true;
	public String reason = null;
	public ECPoint color, eID;

	public Ballot(JsonObject json) {
		color_enc = new ElGamalTuple(json.get("color_enc").getAsJsonObject());
		eID_enc = new ElGamalTuple(json.get("eID_enc").getAsJsonObject());
		vote_enc = new ElGamalTuple(json.get("vote_enc").getAsJsonObject());
		color_part_dec = new ArrayList<>();
		eID_part_dec = new ArrayList<>();

		if (json.get("color_part_dec") != null || json.get("eID_part_dec") != null) {
			JsonArray color_dec_json = json.get("color_part_dec").getAsJsonArray();
			for (JsonElement item : color_dec_json)
				color_part_dec.add(new PartialDecryption(item.getAsJsonObject()));

			JsonArray eID_dec_json = json.get("eID_part_dec").getAsJsonArray();
			for (JsonElement item : eID_dec_json)
				eID_part_dec.add(new PartialDecryption(item.getAsJsonObject()));
		}
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();

		json.add("color_enc", color_enc.toJsonObject());
		json.add("eID_enc", eID_enc.toJsonObject());
		json.add("vote_enc", vote_enc.toJsonObject());

		return json;
	}

	public JsonObject toExtendedJsonObject(boolean finished_decryption) {
		JsonObject json = toJsonObject();

		JsonArray color_part_dec_json = new JsonArray();
		for (PartialDecryption item : color_part_dec)
			color_part_dec_json.add(item.toJsonObject());

		JsonArray eID_part_dec_json = new JsonArray();
		for (PartialDecryption item : eID_part_dec)
			eID_part_dec_json.add(item.toJsonObject());

		json.add("color_part_dec", color_part_dec_json);
		json.add("eID_part_dec", eID_part_dec_json);

		if (finished_decryption) {
			json.addProperty("color", Printer.bytesToHex(color.getEncoded(true)));
			json.addProperty("eID", Printer.bytesToHex(eID.getEncoded(true)));
			json.addProperty("valid", valid);
			if (!valid)
				json.addProperty("reason", reason);
		}

		return json;
	}
}
