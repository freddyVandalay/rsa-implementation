import java.util.*; 
import java.util.Scanner;
import java.math.BigInteger;

public class KeyGeneratorRSA {
	private String userName;
	//Public keys
	private int n;//p*q 
	private int e;//exponent
	
	//Private key
	private int d;//decrypt key
	
	//Other variables
	private int p;//prime 1
	private int q;//prime 2
	private int phiN;
	private int phiP;
	private int phiQ;
	//used for weak encryption
	private int smallMinPrime = 10;
	private int smallMaxPrime = 99;
	//used for strong encryption
	private int largeMinPrime = 1000;
	private int largeMaxPrime = 9999;
	//used to generate public key E
	private int minEPrime = 2;
	private int maxEPrime = 49;

	private int message_length;
	//private String send_message;
	private StringBuilder message;
	//Array that store the message to be sent
	private int [] pT; //plainText
	//Array that store the enrypted message to be sent
	public BigInteger [] cT; //cypherText

	//Authentication variables for part 2
	private int currentNonce;
	private int receivedNonce;
	private int bN;
	private int bE;

	//Constructor
	public KeyGeneratorRSA(int encryptionLevel){
		generatePublicKeys(encryptionLevel);
		generatePrivateKey();
		
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

	//public key N
	public int getN(){
		/*Debug*/ //System.out.println("Value of n: " + n);
		return n;
	}

	//public key e
	public int getE(){
		/*Debug*/ //System.out.println("Value of e: " + e);
		return e;

	}

	//private key
	public int getD(){
		//System.out.println("Value of d: " + d);
		return d;
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
//Start//-----Calculate variables-------///
	private void calculateN() {
		n=p*q;
		/*Debug*/ //System.out.println("phiN is: " + n);
	}

	//Calculate phiN
	private void calculatePhiN() {
		phiN = (p-1)*(q-1);
		/*Debug*/ //System.out.println("phiN is: " + phiN);
	}

	private void calculateE() {
		//Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n)) = 1; i.e., e and λ(n) are coprime. (From Wiki)
		boolean isCoprime=false;
		//1:generate a random number betweem 2 and phiN
		while(!isCoprime){
			e = generateRandNum(minEPrime, maxEPrime); //going for a raher small e
			//check if coprime
			if(coprime(e,phiN))
				isCoprime = true;
		}
	}

	//private decryption key
	private void calculateD() {
		boolean foundK=false;
		int k = 1;
		while(!foundK){
			d = (k*phiN+1)/e;
			if((e*d)%phiN == 1) {
				foundK = true;
				/*Debug*/ //System.out.println("D was found on k = " + k);
				/*Debug*/ //System.out.println("d*e mod n should be one: " +  e + " * " + d + " mod " + phiN + " = " + ((e*d)%phiN));
			}
			k++;
		}
	}
//END//-----Calculate variables-------///
	
	private void encrypt() {
		System.out.println("---------------//Alice START ENCRYPT PROCESS//------------------");
		cT = new BigInteger[pT.length];
		String str = "";
		String strE = "";
		String strN = "";
		BigInteger plainValue;
		BigInteger e;
		BigInteger n;
		BigInteger cipherText;
		strE = Integer.toString(this.e);
		strN = Integer.toString(this.n);
		e = new BigInteger(strE);
		n = new BigInteger(strN);

		for (int i=0;i<message_length;i++){
			//System.out.println(i + " value: " + pT[i]);
			//System.out.println("Decrypt D: " + e);
			//System.out.println("Decrypt N: " + n);

			str = Integer.toString(pT[i]);
			plainValue = new BigInteger(str);
			cipherText = plainValue.modPow(e,n);
			cT[i] = cipherText;
			System.out.println("ENCRYPTED TEXT RESULT: " + (char)pT[i] + " >> " + "Ascii code (" + str + ")" + " >> " + cipherText);
			System.out.println("---------------------------");
		}
		System.out.println("---------------//END ENCRYPT PROCESS//------------------");
	}

	//Used to encrypt Nonces
	private BigInteger[] encrypt(int currentE, int currentN, int[] pT) {
		BigInteger[] cT = new BigInteger[pT.length];
		String str = "";
		String strE = "";
		String strN = "";
		BigInteger plainValue;
		BigInteger e;
		BigInteger n;
		BigInteger cipherText;
		strE = Integer.toString(currentE);
		strN = Integer.toString(currentN);
		e = new BigInteger(strE);
		n = new BigInteger(strN);
		for (int i=0;i<pT.length;i++){
			str = Integer.toString(pT[i]);
			plainValue = new BigInteger(str);
			cipherText = plainValue.modPow(e,n);
			cT[i] = cipherText;
		}

		return cT;
	}	
	
	public void decrypt() {
		System.out.println("---------------//Alice START DECRYPT PROCESS//------------------");
		String str = "";
		String strD = "";
		String strN = "";

		BigInteger cipherValue;
		BigInteger d;
		BigInteger n;
		BigInteger decryptedText;
		pT = new int[cT.length];
		message = new StringBuilder();
		strD = Integer.toString(this.d);
		strN = Integer.toString(this.n);
		d = new BigInteger(strD);
		n = new BigInteger(strN);

		//System.out.println("Decrypt D: " + d);
		//System.out.println("Decrypt N: " + n);
		//cipherValue.add()
		for (int i=0;i<cT.length;i++){
			//System.out.println(i + " value: " + cT[i]);
	
			decryptedText = cT[i].modPow(d,n);
			pT[i] = (char)decryptedText.intValue();
			//System.out.println((char)decryptedText.intValue());
			message.append((char)decryptedText.intValue());
			System.out.println("DECRYPTED TEXT RESULT: " + cT[i] + " >> " + pT[i] + " >> " + (char)pT[i]);
			System.out.println("---------------------------");
		}
		//System.out.println("DECRYPTED Message: " + message);
		System.out.println("---------------//END DECRYPT PROCESS//------------------");
	}

	//For decrypting nonces
	public int[] decrypt(BigInteger[] cT) {
		String str = "";
		String strD = "";
		String strN = "";

		BigInteger cipherValue;
		BigInteger d;
		BigInteger n;
		BigInteger decryptedText;
		int[] pT = new int[cT.length];
		message = new StringBuilder();
		strD = Integer.toString(this.d);
		strN = Integer.toString(this.n);
		d = new BigInteger(strD);
		n = new BigInteger(strN);

		for (int i=0;i<cT.length;i++){
			decryptedText = cT[i].modPow(d,n);
			pT[i] = (char)decryptedText.intValue();

			message.append((char)decryptedText.intValue());
		}

		return pT;
	}

//Start//-----Other Methods-------///

	//convert the plain text message to ascii char by char and store its values in an array
	private void plainTextHandler(String message){
		pT = new int[message.length()];
		for (int i=0;i<pT.length;i++){
			pT[i]=(int)message.charAt(i);
		}
	}

	//Generates a random number between min and max
	private int generateRandNum(int min, int max){
		return min + (int)((Math.random())*(max-min)); 
	}

	//Find a random Prime number between min and max
	private int findPrime(int min, int max) {

		boolean primeFound = false;
		boolean isPrime;
		int randPrime=0;
		int i;
		/*Debug*/ //int round = 1;

		//While prime not found repeat
		while (!primeFound){
			i = 2;
			isPrime = true; //Assume randPrime is a prime
 			randPrime = generateRandNum(min, max);
			/*Debug*/ //System.out.println("Let's try: " + rand);
			primeFound=true; //Assume prime has been found


			while (isPrime && i<=randPrime/2){
				if (randPrime%i == 0){
					isPrime = false;
					/*Debug*/ //System.out.println(randPrime + ", Is not a prime since: " + randPrime + " mod " + i + " = " + randPrime%i);
					/*Debug*/ //System.out.println("Try: " + round);
					/*Debug*/ //round++;
					primeFound=false;
				}
				i++;
			}
		}
		/*Debug*/ //System.out.println("Prime found: " + randPrime);
		return randPrime;
	}

	//Code modiefied from http://www.blackwasp.co.uk/Coprime.aspx
	public int getGCDByModulus(int value1, int value2){
		while (value1 != 0 && value2 != 0){
			if (value1 > value2)
            			value1 %= value2;
        		else
            			value2 %= value1;
       	 	}
        	return Math.max(value1, value2);
    	}

    //Code modified from http://www.blackwasp.co.uk/Coprime.aspx
    public boolean coprime(int value1, int value2)
    {
    	return getGCDByModulus(value1, value2) == 1;
	}
//END//-----Other Methods-------///
}

