//Software prototype that demonstrates how the RSA algorithm works

//use command java menu to execute main program

//Chose what part to run using keyboard
//1: is part 1 of the coursework
//2: is part 2 of the coursework 

//The program does not handle input missmatch exceptions

import java.util.Scanner;
import java.math.BigInteger;

public class menu{

	Alice alice;
	Bob bob;
	Charlie charlie;
	String message;
	int userChoice;
	int selectedPart;
	int selectedSender;
	Scanner scanInput;
	Server server; //used for part 2

	public menu(){
		//User choice of Part 1 or Part 2 of the task
		selectedPart = chosePart();		

		//User choice of weak or strong encryption
		userChoice = choiceEncryption();
		// Plain text Message to be sent
		
		//create alice
		alice = new Alice(userChoice);
		//create bob
		bob = new Bob(userChoice);
		
		//create charlie
		charlie = new Charlie(alice, userChoice);

		//create server object. Used for part 2
		server = new Server(alice.getE(), alice.getN(), bob.getE(), bob.getN(), charlie.getE(), charlie.getN());		

		//User chose what part two run
		if(selectedPart == 1){
				selectedSender = choseSender();
				if(selectedSender == 1){
					message = messageInput();		
					sendToBob();
				}
				else{
					message = messageInput();
					sendToAlice();
				}
		}
		else{
			aliceAndBobAuth();		
		}
		scanInput.close();
	}

	public void sendToBob(){
		System.out.println("");
		System.out.println("From Alice to Bob.");

		alice.setN(bob.getN());
		alice.setE(bob.getE());
		
		System.out.println("Bob gives his public keys too Alice: ");
		System.out.println("	*Bobs N " + bob.getN() + " >>>> Alice");
		System.out.println("	*Bobs e " + bob.getE() + " >>>> Alice");

		alice.sendMessage(message);
		
		System.out.println("");
		System.out.println("Alice enctryps the message using Bobs public keys N and e.");

		System.out.println("Bob receives cyphertext from Alice and decrypts it using his private key d.");
		System.out.println("");
		
		bob.receiveMessage(alice.cT);
		
		System.out.println("");
		System.out.println("Bob reads message: " + bob.readMessage());
		System.out.println("Please wait while Charlie intercepts: ");

		charlie.intercept(alice.getCT());
	}

	public void sendToAlice(){
		System.out.println("");
		System.out.println("From Bob to Alice.");

		bob.setN(alice.getN());
		bob.setE(alice.getE());

		System.out.println("Alice gives her public keys too Bob: ");
		System.out.println("	*Alice N " + alice.getN() + " >>>> Bob");
		System.out.println("	*Alice e " + alice.getE() + " >>>> Bob");

		
		bob.sendMessage(message);
		
		System.out.println("");
		System.out.println("Bob enctryps the message using Alice public keys N and e.");
		
		System.out.println("Alice receives cyphertext from Alice and decrypts it using his private key d.");
		System.out.println("");
		
		alice.receiveMessage(bob.cT);
		
		System.out.println("");
		System.out.println("Alice read message: " + alice.readMessage());
	}

	public void aliceAndBobAuth(){
		System.out.println("<<-----------------------------Start Of Auth--------------------------->>");

		alice.setPartnerPublicKey(server.getBN(), server.getBE());
		System.out.println("ALICE --> SERVER: A, B");
		System.out.println("SERVER --> ALICE: (" + server.getBN() + " - " + server.getBE() + ",B)ks");

		BigInteger[] aNonce = alice.generateNonce();
                bob.receiveNonce(aNonce);
		System.out.println("ALICE --> BOB: (" + aNonce[0] + ", A)Kb");

		bob.setPartnerPublicKey(server.getAN(), server.getAE());
		System.out.println("BOB --> SERVER: B, A");
		System.out.println("SERVER --> BOB: (" + server.getAN() + " - " + server.getAE() + ", A)ks");

		BigInteger[] bNonce = bob.generateNonce();
		aNonce = bob.returnNonce();

		alice.receiveOwnNonce(aNonce);
		alice.receiveNonce(bNonce);
		System.out.println("BOB --> ALICE: (" + aNonce[0] + ", " + bNonce[0] +")Ka");

		bNonce = alice.returnNonce();
		bob.receiveOwnNonce(bNonce);
		System.out.println("ALICE --> BOB: (" + bNonce[0] + ")Kb");
	
		charlieForcedAuth();
	}

	public void charlieForcedAuth(){
		System.out.println("<<-----------------------------Start Of Faked Authentication--------------------------->>");

		charlie.setPartnerPublicKey(server.getAN(), server.getAE());
		System.out.println("CHARLIE --> SERVER: C, A");
                System.out.println("SERVER --> CHARLIE: (" + server.getAN() + " - " + server.getAE() + ",A)ks");

		BigInteger[] cNonce = charlie.generateNonce();
		alice.receiveNonce(cNonce);
		System.out.println("CHARLIE --> ALICE: (" + cNonce[0] + ", B)Ka");

		alice.setPartnerPublicKey(server.getBN(), server.getBE());
		System.out.println("ALICE --> SERVER: A, B");
                System.out.println("SERVER --> ALICE: (" + server.getBN() + " - " + server.getBE() + ", B)ks");

		BigInteger[] aNonce = alice.generateNonce();

		charlie.receiveOwnNonce(cNonce);
		charlie.receiveNonce(aNonce);

		System.out.println("ALICE --> CHARLIE: (" + cNonce[0] + ", " + aNonce[0] +")Kb");

		bob.setPartnerPublicKey(server.getAN(), server.getAE());
		System.out.println("BOB --> SERVER: B, A");
                System.out.println("SERVER --> BOB: (" + server.getAN() + " - " + server.getAE() + ",A)ks");

		aNonce = charlie.returnSpoofedNonce();

		bob.receiveNonce(aNonce);
		System.out.println("CHARLIE --> BOB: (" + aNonce[0] + ", A)Kb");

		BigInteger[] bNonce = bob.generateNonce();
		aNonce = bob.returnNonce();

		charlie.receiveNonce(bNonce);
		charlie.receiveOwnNonce(aNonce);

		System.out.println("BOB --> CHARLIE: (" + aNonce[0] + ", " + bNonce[0] +")Ka");

		aNonce = charlie.returnSpoofedNonce();

		alice.receiveOwnNonce(aNonce);
		System.out.println("CHARLIE --> ALICE: (" + aNonce[0] + ")Ka");
	}

	public String messageInput(){
		String m; 

		System.out.println("Input message to be sent: ");
		scanInput = new Scanner(System.in);
		m = scanInput.nextLine();
		return m;

	}

	public int choiceEncryption(){
		int choice=2;
		boolean validChoice=false;
		while (!validChoice){
			System.out.println("Please, make a choice. ");
			System.out.println("1: Weak encryption (2 digit primes)");
			System.out.println("2: Strong encryption (4 digit primes)");
			scanInput = new Scanner(System.in);
			choice = scanInput.nextInt();
			if(choice==1 || choice==2){
				validChoice = true;
			}
		}
		return choice;
	}

	public int chosePart(){
		int choice=2;
		boolean validChoice=false;
		while (!validChoice){
			System.out.println("Please, chose which part to run.");
			System.out.println("1: Part 1 - RSA Message Encryption and Brute Force Attack)");
			System.out.println("2: Part 2 - RSA Nonce Authentication");
			scanInput = new Scanner(System.in);
			choice = scanInput.nextInt();
			if(choice==1 || choice==2){
				validChoice = true;
			}
		}
		return choice;
	}

	public int choseSender(){
		int choice=2;
		boolean validChoice=false;
		while (!validChoice){
			System.out.println("Please, make a choice. (Charlie only intercepts messages from Alice to Bob)");
			System.out.println("1: Send a message to Bob from Alice");
			System.out.println("2: Send a message to Alice from Bob");
			scanInput = new Scanner(System.in);
			choice = scanInput.nextInt();
			if(choice==1 || choice==2){
				validChoice = true;
			}
		}
		return choice;
	}

	public static void main(String args[]){
		new menu();	
	}
}
