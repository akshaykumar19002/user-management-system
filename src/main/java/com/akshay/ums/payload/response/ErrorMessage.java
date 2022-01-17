package com.akshay.ums.payload.response;

import java.util.Date;

public class ErrorMessage {

	private int httpStatus;
	
	private Date time;
	
	private String message;
	
	private String description;
	
	public ErrorMessage(int httpStatus, Date time, String message, String description) {
		super();
		this.httpStatus = httpStatus;
		this.time = time;
		this.message = message;
		this.description = description;
	}

	public int getHttpStatus() {
		return httpStatus;
	}

	public void setHttpStatus(int httpStatus) {
		this.httpStatus = httpStatus;
	}

	public Date getTime() {
		return time;
	}

	public void setTime(Date time) {
		this.time = time;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
	
}
