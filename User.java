import java.util.*; 
import java.util.Scanner;
import java.math.BigInteger;

public class User {
	private String userName;
	
	//Public keys
	private int n;//p*q 
	private int e;//exponent
	
	//Private key
	private int d;//decrypt key
	
	KeyGeneratorRSA keyGenertor;
	
	//Other variables
	private int p;//prime 1
	private int q;//prime 2
	private int phiN;
	private int phiP;
	private int phiQ;

	private int message_length;
	//private String send_message;
	private StringBuilder message;
	
	//Array that store the message to be sent
	private int [] pT;
	//Array that store the enrypted message to be sent
	public BigInteger [] cT;



	//Constructor
	public User(String userName, int encryptionLevel){
		keyGenertor = new KeyGeneratorRSA();
		setUserName(userName);
		generatePublicKeys(encryptionLevel);
		generatePrivateKey();
		
		System.out.println(">>>" + userName + "<<< ");
		System.out.println("Public Keys:");
		System.out.println("n = " + n);
		System.out.println("e = " + e);
		
		/*Debug*/ /*
		System.out.println(">>>Variables<<< ");
		System.out.println("p = " + p);
		System.out.println("q = " + q);
		System.out.println("n = " + n);
		System.out.println("phiN = " + phiN);
		System.out.println("e = " + e);
		System.out.println("d = " + d);
		*/
	}

	private String setUserName(String userName){
		String this.userName = userName;
		
	}
	public String getUserName(){
		return this.userName;
	}

	//part 2 method
	public void setPartnerPublicKey(int _bN, int _bE){
		bN = _bN;
		bE = _bE;
	}

	//part 2 method
	public BigInteger[] generateNonce(){
		currentNonce = generateRandNum(1, 100);

		pT = new int[1];
		pT[0] = currentNonce;

		return encryptNonce(pT);
	}
	
	//part 2 method
	public BigInteger[] encryptNonce(int[] nonce){
		return encrypt(bE, bN, nonce);
	}
	
	//part 2 method
	public int[] decryptNonce(BigInteger[] nonce){
		return decrypt(nonce);
	}
	
	//part 2 method
	public void receiveNonce(BigInteger [] _cT){
                int[] nonces = decryptNonce(_cT);

		receivedNonce = nonces[0];
        }

	//part 2 method
	public void receiveOwnNonce(BigInteger[] nonce){
		if(verifyNonce(decryptNonce(nonce))){
			System.out.println("ALICE: BOB AUTHENTICATED");
		}
	}

	//part 2 method
	public boolean verifyNonce(int[] nonce){
		if(nonce[0] == currentNonce){
			return true;
		}

		return false;
	}

	//part 2 method
	public BigInteger[] returnNonce(){
		int[] rN = new int[1];
		rN[0] = receivedNonce;

		return encryptNonce(rN);

	}



	public BigInteger[] getCT(){
		return cT;
	}

	//public key N
	public void setN(int n){
		this.n = n;
	}
	//public key e
	public void setE(int e){
		this.e = e;

	}

	private void generatePublicKeys(int encryptLevel){
		//weak decrytion
		if (encryptLevel == 1){
			p=findPrime(smallMinPrime,smallMaxPrime);
			q=findPrime(smallMinPrime,smallMaxPrime);
		}
		//"Strong" decryption
		else{
			p=findPrime(largeMinPrime,largeMaxPrime);
			q=findPrime(largeMinPrime,largeMaxPrime);
		}
		//calculate variables
		calculateN();
		calculatePhiN();
		calculateE();
	}

	private void generatePrivateKey(){
		calculateD();
	}

	public void sendMessage(String m){
		message_length = m.length();
		plainTextHandler(m);
		encrypt();
	}

	public void receiveMessage(BigInteger [] _cT){
		message_length = _cT.length; 
		cT = _cT;
		decrypt();
	}

	public StringBuilder readMessage(){
		return message;
	}
}

