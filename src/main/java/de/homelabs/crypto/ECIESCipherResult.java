package de.homelabs.crypto;

public class ECIESCipherResult {

	private boolean successfull = false;
	private String lastError = "";
	private byte[] result;
	
	public ECIESCipherResult(boolean successfull, String lastError, byte[] result) {
		super();
		this.successfull = successfull;
		this.lastError = lastError;
		this.result = result;
	}
	/**
	 * @return the successful
	 */
	public boolean isSuccessfull() {
		return successfull;
	}
	/**
	 * @return the lastError
	 */
	public String getLastError() {
		return lastError;
	}
	/**
	 * @return the result
	 */
	public byte[] getResult() {
		return result;
	}
}
