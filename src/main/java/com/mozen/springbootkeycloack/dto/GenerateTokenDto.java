/**
 * 
 */
package com.mozen.springbootkeycloack.dto;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 25, 2023
 */
public class GenerateTokenDto {
	public String sessionId;
	public String msisdn;
	public String password;
	public String pin;
	public String nonce;
	public int ttlMin;
	public String userCategory;

	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public String getMsisdn() {
		return msisdn;
	}

	public void setMsisdn(String msisdn) {
		this.msisdn = msisdn;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPin() {
		return pin;
	}

	public void setPin(String pin) {
		this.pin = pin;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public int getTtlMin() {
		return ttlMin;
	}

	public void setTtlMin(int ttlMin) {
		this.ttlMin = ttlMin;
	}

	public String getUserCategory() {
		return userCategory;
	}

	public void setUserCategory(String userCategory) {
		this.userCategory = userCategory;
	}
}
