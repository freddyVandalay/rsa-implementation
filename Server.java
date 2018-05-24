import java.math.BigInteger;

public class Server{

	private int aE, aN;//Alice's key
	private int bE, bN;//Bob's key
	private int cE, cN;//Charlie's key

	public Server(int _aE, int _aN, int _bE, int _bN, int _cE, int _cN){
		aE = _aE;
		aN = _aN;
		bE = _bE;
		bN = _bN;
		cE = _cE;
		cN = _cN;
	}

	public int getAE(){
		return aE;
	}

	public int getAN(){
		return aN;
	}

	public int getBE(){
		return bE;
	}

	public int getBN(){
		return bN;
	}

	public int getCE(){
		return cE;
	}

	public int getCN(){
		return cN;
	}
}
