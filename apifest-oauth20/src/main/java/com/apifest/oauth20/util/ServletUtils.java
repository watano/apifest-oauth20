package com.apifest.oauth20.util;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jodd.io.StreamUtil;

public class ServletUtils {
	public static String getContent(HttpServletRequest request){
		String content = null;
		try {
			content = new String(StreamUtil.readBytes(request.getReader(), "utf-8"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return content;
	}
}
