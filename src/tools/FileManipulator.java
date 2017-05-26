package tools;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class FileManipulator {
	public static final String BallotBoardFilename = "ballot_board.json";
	public static final String ElectionFilename = "election.json";
	public static final String VoteBoardFilename = "vote_board.json";
	public static final String ResultFilename = "result.json";
	
	private static Gson gson = new GsonBuilder().setPrettyPrinting().create();
	private static JsonParser parser = new JsonParser();
	
	public static void writeToFile(String fileName, JsonElement json) {
		try {
			FileWriter writer = new FileWriter(new File(fileName));
			writer.write(gson.toJson(json));
			writer.flush();
			writer.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

	public static JsonObject readJsonObjectFromFile(String fileName) {
		try {
			FileReader reader = new FileReader(new File(fileName));
			JsonObject json = parser.parse(reader).getAsJsonObject();
			return json;
		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static JsonArray readJsonArrayFromFile(String fileName) {
		try {
			FileReader reader = new FileReader(new File(fileName));
			JsonArray json = parser.parse(reader).getAsJsonArray();
			return json;
		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		}
		return null;
	}
}
