package main;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import data.Ballot;
import data.Candidate;
import data.ElGamalTuple;
import data.Election;
import data.ElectionKey;
import data.Vote;
import tools.Crypto;
import tools.FileManipulator;
import tools.GitManipulator;
import tools.Printer;

public class Main {

	public static void main(String[] args) {
		Scanner scan = new Scanner(System.in);
		boolean running = true;
		Election election = null;
		Teller teller = null;

		while (running) {
			printMenu();
			String line = scan.nextLine().trim();
			String[] words = line.split(" ");
			int menu_item = Integer.parseInt(words[0]);
			switch (menu_item) {
			case 0: {// exit
				running = false;
				break;
			}
			case 1: {
				GitManipulator.initialize();

				break;
			}
			case 2: {
				BigInteger x = BigInteger.probablePrime(256, new SecureRandom()).mod(Crypto.curve.getN());
				teller = new Teller(x);

				JsonObject json = new JsonObject();
				json.addProperty("x", Printer.bytesToHex(x.toByteArray()));
				FileManipulator.writeToFile(FileManipulator.getPrivatekeyFilename(), json);

				updateElectionKeyFile(teller.y);
				break;
			}
			case 3: {
				try {
					JsonObject private_key_json = FileManipulator
							.readJsonObjectFromFile(FileManipulator.getPrivatekeyFilename());
					teller = new Teller(private_key_json);
					updateElectionKeyFile(teller.y);
				} catch (Exception e) {
					System.out.println("Couldn't read private key file");
				}

				break;
			}
			case 4: {
				if (teller == null) {
					System.out.println("You need to initialize first.");
					break;
				}

				try {
					List<Ballot> ballot_board = new ArrayList<>();
					JsonArray ballots_json = FileManipulator
							.readJsonArrayFromFile(FileManipulator.getDecryptionBallotBoardFilename());
					for (JsonElement item : ballots_json)
						ballot_board.add(new Ballot(item.getAsJsonObject()));

					teller.applyBallotPartialDecryption(ballot_board);

					JsonArray json = new JsonArray();
					for (Ballot item : ballot_board)
						json.add(item.toExtendedJsonObject(false));
					FileManipulator.writeToFile(FileManipulator.getDecryptionBallotBoardFilename(), json);

					System.out.println("Ballot partial decryption applied");
				} catch (Exception e) {
					System.out.println("Couldn't read decryption ballot board file");
				}
				break;
			}
			case 5: {
				if (teller == null) {
					System.out.println("You need to initialize first.");
					break;
				}

				try {
					List<Vote> vote_board = new ArrayList<>();
					JsonArray votes_json = FileManipulator
							.readJsonArrayFromFile(FileManipulator.getDecryptionVoteBoardFilename());
					for (JsonElement item : votes_json)
						vote_board.add(new Vote(item.getAsJsonObject()));

					teller.applyVotePartialDecryption(vote_board);

					JsonArray json = new JsonArray();
					for (Vote item : vote_board)
						json.add(item.toExtendedJsonObject(false));
					FileManipulator.writeToFile(FileManipulator.getDecryptionVoteBoardFilename(), json);

					System.out.println("Vote partial decryption applied");
				} catch (Exception e) {
					System.out.println("Couldn't read decryption vote board file");
				}
				break;
			}
			case 6: {
				try {
					JsonObject election_json = FileManipulator
							.readJsonObjectFromFile(FileManipulator.getElectionFilename());
					election = new Election(election_json);
				} catch (Exception e) {
					System.out.println("Couldn't read election file");
					break;
				}

				try {
					List<Ballot> ballot_board = new ArrayList<>();
					JsonArray ballots_json = FileManipulator
							.readJsonArrayFromFile(FileManipulator.getDecryptionBallotBoardFilename());
					for (JsonElement item : ballots_json)
						ballot_board.add(new Ballot(item.getAsJsonObject()));

					ECPoint h = Crypto.sumOfPointsStream(election.L);
					List<ECPoint> existing_eIDs = new ArrayList<>();
					List<ECPoint> duplicate_eIDs = new ArrayList<>();

					for (Ballot ballot : ballot_board) {
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

					for (Ballot ballot : ballot_board)
						if (duplicate_eIDs.contains(ballot.eID)) {
							ballot.valid = false;
							ballot.reason = "Multiple vote";
						}
										
					JsonArray json = new JsonArray();
					for (Ballot item : ballot_board)
						json.add(item.toExtendedJsonObject(true));
					FileManipulator.writeToFile(FileManipulator.getDecryptionBallotBoardFilename(), json);
					
					List<ElGamalTuple> votes_enc = ballot_board.stream().filter(b -> b.valid).map(b -> b.vote_enc)
							.collect(Collectors.toList());

					JsonArray votes_enc_json = new JsonArray();
					for (ElGamalTuple item : votes_enc)
						votes_enc_json.add(item.toJsonObject());
					FileManipulator.writeToFile(FileManipulator.getVoteBoardFilename(0), votes_enc_json);
				} catch (Exception e) {
					System.out.println("Couldn't read decryption ballot board file");
				}
				break;
			}
			case 7: {
				try {
					JsonObject election_json = FileManipulator
							.readJsonObjectFromFile(FileManipulator.getElectionFilename());
					election = new Election(election_json);
				} catch (Exception e) {
					System.out.println("Couldn't read election file");
					break;
				}
				
				List<Candidate> candidates = election.candidates.stream().map(name -> new Candidate(name))
						.collect(Collectors.toList());
				
				try {
					List<Vote> vote_board = new ArrayList<>();
					JsonArray votes_json = FileManipulator
							.readJsonArrayFromFile(FileManipulator.getDecryptionVoteBoardFilename());
					for (JsonElement item : votes_json)
						vote_board.add(new Vote(item.getAsJsonObject()));

					List<String> received_votes = new ArrayList<>();
					for (Vote vote : vote_board) {
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

					JsonArray json = new JsonArray();
					for (Vote item : vote_board)
						json.add(item.toExtendedJsonObject(true));
					FileManipulator.writeToFile(FileManipulator.getDecryptionVoteBoardFilename(), json);
					
					JsonArray received_votes_json = new JsonArray();
					for (String item : received_votes)
						received_votes_json.add(new JsonPrimitive(item));
					FileManipulator.writeToFile(FileManipulator.getResultFilename(), received_votes_json);

					System.out.println("Vote partial decryption applied");
				} catch (Exception e) {
					System.out.println("Couldn't read decryption vote board file");
				}
				break;
			}
			case 8: {
				System.out.println("Not implemented yet");
				break;
			}
			case 9: {
				System.out.println("Not implemented yet");
				break;
			}
			case 10: {
				GitManipulator.pushGitRepo();
				break;
			}
			default: {
				System.out.println("You need to specify one of the options.");
				break;
			}
			}
		}
		scan.close();
	}

	private static void updateElectionKeyFile(ECPoint y) {
		ElectionKey election_key;
		try {
			JsonObject election_key_json = FileManipulator
					.readJsonObjectFromFile(FileManipulator.getElectionKeyFilename());
			election_key = new ElectionKey(election_key_json);
		} catch (Exception e) {
			election_key = new ElectionKey();
		}
		if (election_key.addPublicKey(y)) {
			System.out.println("New public key added: " + Printer.bytesToHex(y.getEncoded(true)));
			FileManipulator.writeToFile(FileManipulator.getElectionKeyFilename(), election_key.toJsonObject());
		} else
			System.out.println("Public key already existed: " + Printer.bytesToHex(y.getEncoded(true)));
	}

	private static void printMenu() {
		int i = 0;
		System.out.println();
		System.out.println("To exit                        press  " + i++); // 0
		System.out.println("To pull git repo               press  " + i++); // 1
		System.out.println("To generate private/public key press  " + i++); // 2
		System.out.println("To instatiate teller from file press  " + i++); // 3
		System.out.println("To partially decrypt ballots   press  " + i++); // 4
		System.out.println("To partially decrypt vote      press  " + i++); // 5
		System.out.println("To finalize ballot board       press  " + i++); // 6
		System.out.println("To finalize vote board         press  " + i++); // 7
		System.out.println("To check ballot decryptions    press  " + i++); // 8
		System.out.println("To check vote decryptions      press  " + i++); // 9
		System.out.println("To push git repo               press  " + i++); // 10
	}

}
