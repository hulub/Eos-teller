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
	private static final String BallotBoardFilename = "ballot_board", VoteBoardFilename = "vote_board",
			ElectionFilename = "election", ending = ".json", PrivateKeyFilename = "private_key",
			ElectionKeyFilename = "election_key", ResultFilename = "result",
			DecryptionBallotBoardFilename = "decryption_" + BallotBoardFilename,
			DecryptionVoteBoardFilename = "decryption_" + VoteBoardFilename;
	private static final String separator = System.getProperty("os.name").contains("Windows") ? "\\" : "/";
	private static final String eos_path = "eos" + separator, ballot_path = eos_path + "mixed_ballots" + separator,
			vote_path = eos_path + "mixed_votes" + separator;

	private static Gson gson = new GsonBuilder().setPrettyPrinting().create();
	private static JsonParser parser = new JsonParser();

	public static String getEosFilename() {
		return eos_path;
	}

	public static String getElectionFilename() {
		return eos_path + ElectionFilename + ending;
	}

	public static String getElectionKeyFilename() {
		return eos_path + ElectionKeyFilename + ending;
	}

	public static String getPrivatekeyFilename() {
		return PrivateKeyFilename + ending;
	}

	public static String getDecryptionBallotBoardFilename() {
		return eos_path + DecryptionBallotBoardFilename + ending;
	}

	public static String getDecryptionVoteBoardFilename() {
		return eos_path + DecryptionVoteBoardFilename + ending;
	}

	public static String getResultFilename() {
		return eos_path + ResultFilename + ending;
	}

	public static String getBallotBoardFilename(int i) {
		if (i == 0)
			return eos_path + BallotBoardFilename + ending;
		else {
			File directory = new File(ballot_path);
			if (!directory.exists() && !directory.mkdirs()) {
				System.out.println("Couldn't create dir: " + directory);
				return eos_path + BallotBoardFilename + "_" + i + ending;
			}
			return ballot_path + BallotBoardFilename + "_" + i + ending;
		}
	}

	public static String getVoteBoardFilename(int i) {
		if (i == 0)
			return eos_path + VoteBoardFilename + ending;
		else {
			File directory = new File(vote_path);
			if (!directory.exists() && !directory.mkdirs()) {
				System.out.println("Couldn't create dir: " + directory);
				return eos_path + VoteBoardFilename + "_" + i + ending;
			}
			return vote_path + VoteBoardFilename + "_" + i + ending;
		}
	}

	public static void writeToFile(String fileName, JsonElement json) {
		try {
			FileWriter writer = new FileWriter(new File(fileName));
			writer.write(gson.toJson(json));
			writer.flush();
			writer.close();
		} catch (IOException ex) {
			System.out.println("Problem reading file");
		}
	}

	public static JsonObject readJsonObjectFromFile(String fileName) {
		try {
			FileReader reader = new FileReader(new File(fileName));
			JsonObject json = parser.parse(reader).getAsJsonObject();
			reader.close();
			return json;
		} catch (FileNotFoundException ex) {
			System.out.println("Couldn't find file " + fileName);
		} catch (IOException e) {
			System.out.println("Problem reading file");
		}
		return null;
	}

	public static JsonArray readJsonArrayFromFile(String fileName) {
		try {
			FileReader reader = new FileReader(new File(fileName));
			JsonArray json = parser.parse(reader).getAsJsonArray();
			reader.close();
			return json;
		} catch (FileNotFoundException ex) {
			System.out.println("Couldn't find file " + fileName);
		} catch (IOException e) {
			System.out.println("Problem reading file");
		}
		return null;
	}
}
