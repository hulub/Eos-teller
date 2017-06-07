package data;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import tools.Printer;

public class Vote {
	public final ElGamalTuple vote_enc;
	public List<PartialDecryption> vote_part_dec = new ArrayList<>();
	public boolean valid = true;
	public ECPoint vote;

	public Vote(JsonObject json) {
		vote_enc = new ElGamalTuple(json.get("vote_enc").getAsJsonObject());
		vote_part_dec = new ArrayList<>();

		if (json.get("vote_part_dec") != null) {
			JsonArray vote_dec_json = json.get("vote_part_dec").getAsJsonArray();
			for (JsonElement item : vote_dec_json)
				vote_part_dec.add(new PartialDecryption(item.getAsJsonObject()));
		}
	}

	public Vote(ElGamalTuple vote_enc) {
		this.vote_enc = vote_enc;
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();

		json.add("vote_enc", vote_enc.toJsonObject());

		return json;
	}

	public JsonObject toExtendedJsonObject(boolean finished_decryption) {
		JsonObject json = toJsonObject();

		JsonArray vote_part_dec_json = new JsonArray();
		for (PartialDecryption item : vote_part_dec)
			vote_part_dec_json.add(item.toJsonObject());

		json.add("vote_part_dec", vote_part_dec_json);
		if (finished_decryption) {
			json.addProperty("vote", Printer.bytesToHex(vote.getEncoded(true)));
			json.addProperty("valid", valid);
		}

		return json;
	}
}
