import java.math.BigInteger;

public class Charlie{

	Alice alice;

	private int e;
	private int n;
	private int d;

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
        private int [] pT;
        //Array that store the enrypted message to be sent
        public BigInteger [] cT;

	private int currentNonce;
	private int receivedNonce;
	private BigInteger[] spoofedNonce;

	private int bN;
	private int bE;

	public Charlie(Alice _alice, int encryptionLevel){
		alice = _alice;

		generatePublicKeys(encryptionLevel);
                generatePrivateKey();
	}

	public void intercept(BigInteger[] cipherText){
		bruteForceAttack(cipherText, alice.getE(), alice.getN());
	}

	//Finds d to decrypt intercepted messages
	public void bruteForceAttack(BigInteger[] cipherText, int e, int n){
		int[] pT = {65, 32};
                BigInteger[] cT = encrypt(pT, e, n);

		boolean found = false;

		int d = -1;

		while(!found){
			d++;

			BigInteger[] currentPT = decrypt(d, cT, n);

			found = true;
			for(int i = 0; i < currentPT.length; i++){
				if(currentPT[i].intValue() != pT[i]){
					found = false;
					break;
				}
			}
		}

		BigInteger[] plainText = decrypt(d, cipherText, n);

		String m = "";

		for(int i = 0; i < plainText.length; i++){
			int val = plainText[i].intValue();
			m += (char) val;
		}

		System.out.println("Real D: " + alice.getD() + " -- Found: " + d);
		System.out.println("Charlies decrypted text: " + m);
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
        public void receiveNonce(BigInteger [] _cT){
		//Charlie can't decrypt this, it is decrypted with someone elses key
		//it is just held on to, to impersonate someone else
		spoofedNonce = _cT;
        }

        //part 2 method
        public void receiveOwnNonce(BigInteger[] nonce){
		spoofedNonce = nonce;
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

	//part 2 method
	public BigInteger[] returnSpoofedNonce(){
                return spoofedNonce;
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

	private BigInteger[] encrypt(int[] pT, int _e, int _n) {
                BigInteger[] cT = new BigInteger[pT.length];
                String str = "";
                String strE = "";
                String strN = "";
                BigInteger plainValue;
                BigInteger e;
                BigInteger n;
                BigInteger plainText;

                strE = Integer.toString(_e);
                strN = Integer.toString(_n);
                e = new BigInteger(strE);
                n = new BigInteger(strN);
                for (int i=0;i<pT.length;i++){

                        str = Integer.toString(pT[i]);
                        plainValue = new BigInteger(str);
                        plainText = plainValue.modPow(e,n);
                        cT[i] = plainText; //m^e mod n
                }

		return cT;
        }

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

	private BigInteger[] decrypt(int currentD, BigInteger[] cT, int _n) {
                String str = "";
                String strD = "";
                String strN = "";

                BigInteger cipherValue;
                BigInteger d;
                BigInteger n;
                BigInteger[] decryptedText = new BigInteger[cT.length];
                strD = Integer.toString(currentD);
                strN = Integer.toString(_n);
                d = new BigInteger(strD);
                n = new BigInteger(strN);

                for (int i=0;i<cT.length;i++){
                        decryptedText[i] = cT[i].modPow(d,n);
                }

		return decryptedText;
        }

	//---------------------------------------Key Generation----------------------------------//
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
}
