package main;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import data.Ballot;
import data.Candidate;
import data.ElGamalTuple;
import data.Election;
import data.Vote;
import tools.Crypto;
import tools.FileManipulator;
import tools.Printer;

public class Main {
	public static ECParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");

	public static void main(String[] args) {
		Scanner scan = new Scanner(System.in);
		boolean running = true;
		List<Teller> tellers = new ArrayList<>();
		Election election = null;

		while (running) {
			printMenu();
			String line = scan.nextLine().trim();
			String[] words = line.split(" ");
			int menu_item = Integer.parseInt(words[0]);
			switch (menu_item) {
			case 0: // exit
				running = false;
				break;
			case 1: // generate tellers, first parameter is #tellers
				if (words.length > 1)
					try {
						int n = Integer.parseInt(words[1]);
						for (int i = 0; i < n; i++)
							tellers.add(new Teller());

						System.out.println(n + " tellers have been generated. Public keys:");
						tellers.stream().forEach(t -> System.out.println(Printer.bytesToHex(t.y.getEncoded(true))));

						break;
					} catch (Exception e) {
						System.out.println("Argument #tellers has to be a number");
						break;
					}
				System.out.println("You need one more argument.");
				break;
			case 2: // generate teller from private key file
				if (words.length > 1) {
					String filename = words[1];
					JsonObject json = FileManipulator.readJsonObjectFromFile(filename);
					try {
						BigInteger x = new BigInteger(1, Printer.hexToBytes(json.get("x").getAsString()));
						Teller t = new Teller(x);
						tellers.add(t);

						System.out.println("New teller added with public key:");
						System.out.println(Printer.bytesToHex(t.y.getEncoded(true)));
						break;
					} catch (Exception e) {
						System.out.println("Wrong file given");
						break;
					}
				}
				System.out.println("You need one more argument.");
				break;
			case 3: // print private key files
				int i = 0;
				for (Teller t : tellers)
					writeTellerPrivateKeyJSON(i++, t.getPrivateKey());

				System.out.println("Private keys written to files.");
				break;
			case 4: // print public key file
				List<ECPoint> y_list = tellers.stream().map(t -> t.y).collect(Collectors.toList());
				writeTellersPublicKeyJSON(y_list);

				System.out.println("Public keys written to file.");
				break;
			case 5:
				try {
					election = new Election(FileManipulator.readJsonObjectFromFile(FileManipulator.ElectionFilename));
				} catch (NullPointerException e) {
					System.out.println("Could not find election file");
					break;
				}

				if (tellers.size() == 0) {
					System.out.println("No tellers available");
					break;
				}
				List<Ballot> ballots = new ArrayList<>();
				JsonArray ballots_json = FileManipulator.readJsonArrayFromFile(FileManipulator.BallotBoardFilename);
				for (JsonElement item : ballots_json)
					ballots.add(new Ballot(item.getAsJsonObject()));

				for (Teller t : tellers)
					t.applyBallotPartialDecryption(ballots);

				ECPoint h = election.L.stream()
						.reduce(Crypto.curve.getCurve().getInfinity(), (y_i, y_j) -> y_i.add(y_j)).normalize();
				List<ECPoint> existing_eIDs = new ArrayList<>();
				List<ECPoint> duplicate_eIDs = new ArrayList<>();

				for (Ballot ballot : ballots) {
					ECPoint color_S = ballot.color_part_dec.stream().map(p -> p.S)
							.reduce(Crypto.curve.getCurve().getInfinity(), (s_i, s_j) -> s_i.add(s_j)).normalize();
					ballot.color = ballot.color_enc.C.subtract(color_S).normalize();

					ECPoint eID_S = ballot.eID_part_dec.stream().map(p -> p.S)
							.reduce(Crypto.curve.getCurve().getInfinity(), (s_i, s_j) -> s_i.add(s_j)).normalize();
					ballot.eID = ballot.eID_enc.C.subtract(eID_S).normalize();

					if (ballot.color.isInfinity()) {
						ballot.valid = false;
						ballot.reason = "Ballot is coerced";
					} else if (!ballot.color.equals(h)) {
						ballot.valid = false;
						ballot.reason = "Ballot is not well-formed";
					} else {
						if (existing_eIDs.contains(ballot.eID))
							duplicate_eIDs.add(ballot.eID);
						else
							existing_eIDs.add(ballot.eID);
					}
				}

				for (Ballot ballot : ballots)
					if (duplicate_eIDs.contains(ballot.eID)) {
						ballot.valid = false;
						ballot.reason = "Multiple vote";
					}

				JsonArray ballots_extended_json = new JsonArray();
				for (Ballot item : ballots)
					ballots_extended_json.add(item.toExtendedJsonObject());
				FileManipulator.writeToFile(FileManipulator.BallotBoardFilename, ballots_extended_json);

				List<ElGamalTuple> votes_enc = ballots.stream().filter(b -> b.valid).map(b -> b.vote_enc)
						.collect(Collectors.toList());

				JsonArray votes_enc_json = new JsonArray();
				for (ElGamalTuple item : votes_enc)
					votes_enc_json.add(item.toJsonObject());
				FileManipulator.writeToFile(FileManipulator.VoteBoardFilename, votes_enc_json);

				break;
			case 6:
				try {
					election = new Election(FileManipulator.readJsonObjectFromFile(FileManipulator.ElectionFilename));
				} catch (NullPointerException e) {
					System.out.println("Could not find election file");
					break;
				}

				if (tellers.size() == 0) {
					System.out.println("No tellers available");
					break;
				}

				List<Candidate> candidates = election.candidates.stream().map(name -> new Candidate(name))
						.collect(Collectors.toList());

				List<Vote> votes = new ArrayList<>();
				JsonArray votes_json = FileManipulator.readJsonArrayFromFile(FileManipulator.VoteBoardFilename);
				for (JsonElement item : votes_json)
					votes.add(new Vote(new ElGamalTuple(item.getAsJsonObject())));

				for (Teller t : tellers)
					t.applyVotePartialDecryption(votes);

				List<String> received_votes = new ArrayList<>();
				for (Vote vote : votes) {
					ECPoint vote_S = vote.vote_part_dec.stream().map(p -> p.S)
							.reduce(Crypto.curve.getCurve().getInfinity(), (s_i, s_j) -> s_i.add(s_j)).normalize();
					vote.vote = vote.vote_enc.C.subtract(vote_S).normalize();

					boolean found = false;
					for (Candidate c : candidates)
						if (c.v.equals(vote.vote)) {
							received_votes.add(c.name);
							found = true;
						}
					vote.valid = found;
				}

				JsonArray votes_extended_json = new JsonArray();
				for (Vote item : votes)
					votes_extended_json.add(item.toExtendedJsonObject());
				FileManipulator.writeToFile(FileManipulator.VoteBoardFilename, votes_extended_json);

				JsonArray received_votes_json = new JsonArray();
				for (String item : received_votes)
					received_votes_json.add(new JsonPrimitive(item));
				FileManipulator.writeToFile(FileManipulator.ResultFilename, received_votes_json);

				break;
			default:
				System.out.println("You need to specify one of the options.");
				break;
			}
		}
		scan.close();
	}

	private static void printMenu() {
		int i = 0;
		System.out.println();
		System.out.println("To exit                        press  " + i++); // 0
		System.out.println("To generate tellers            press  " + i++ + " #tellers"); // 1
		System.out.println("To generate teller from file   press  " + i++ + " file_name");// 2
		System.out.println("To print private key files     press  " + i++); // 3
		System.out.println("To print public key file       press  " + i++); // 4
		System.out.println("To partially decrypt ballots   press  " + i++); // 5
		System.out.println("To partially decrypt votes     press  " + i++); // 6
	}

	private static void writeTellersPublicKeyJSON(List<ECPoint> list) {
		ECPoint Y = list.stream().reduce(curve.getCurve().getInfinity(), (y_1, y_2) -> y_1.add(y_2)).normalize();

		JsonObject json = new JsonObject();

		JsonArray y_list_json = new JsonArray();
		for (ECPoint y : list)
			y_list_json.add(new JsonPrimitive(Printer.bytesToHex(y.getEncoded(true))));

		json.add("y_list", y_list_json);
		json.addProperty("Y", Printer.bytesToHex(Y.getEncoded(true)));

		FileManipulator.writeToFile("tellers_publickey.json", json);
	}

	private static void writeTellerPrivateKeyJSON(int id, BigInteger x) {
		JsonObject json = new JsonObject();
		json.addProperty("x", Printer.bytesToHex(x.toByteArray()));

		FileManipulator.writeToFile("teller_" + id + "_privatekey.json", json);
	}
}
