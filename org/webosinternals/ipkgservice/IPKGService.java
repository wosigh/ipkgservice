/* IPKGService.java - Service to support package management */
/* ------------------------------------------------------------------------- */
/*
  Copyright (C) 2009 WebOS Internals <http://www.webos-internals.org/>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.		     */
/* ------------------------------------------------------------------------- */

package org.webosinternals.ipkgservice;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.palm.luna.LSException;
import com.palm.luna.service.LunaServiceThread;
import com.palm.luna.service.ServiceMessage;
import com.palm.luna.message.ErrorMessage;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class IPKGService extends LunaServiceThread {

    /* ============================== Variables ==============================*/
    private static final String ipkgBaseCommand = "/usr/bin/ipkg -o /var ";
    private static final String ipkgConfigDirPath = "/var/etc/ipkg";
    private static final String ipkgScriptBasePath = "/var/usr/lib/ipkg/info/";
    private static final String ipkgListsBasePath = "/var/usr/lib/ipkg/lists/";
    private static final String ipkgStatusPath = "/var/usr/lib/ipkg/status";

    File ipkgconfdir;
    boolean ipkgReady = false;
    boolean isEmulator = false;
    SessionIDGenerator idgen = new SessionIDGenerator();
    private HashMap<String, ServiceMessage> confirmations = new HashMap<String, ServiceMessage>();

    /**
     * An object to hold the return value, stdout and stderr of the executed command.
     */
    private class ReturnResult {
	int returnValue;
	ArrayList<String> stdOut;
	ArrayList<String> stdErr;
	public ReturnResult(int returnValue, ArrayList<String> stdOut, ArrayList<String> stdErr) {
	    this.returnValue = returnValue;
	    this.stdOut = stdOut;
	    this.stdErr = stdErr;
	}
    }
	
    /**
     * Create a new IPKGService
     */
    public IPKGService() {
	File buildinfo = new File("/etc/palm-build-info");
	isEmulator = readFile(buildinfo, " ").contains("BUILDNAME=Nova-SDK");
	ipkgconfdir = new File(ipkgConfigDirPath);
	if (ipkgconfdir.exists()) {
	    if (ipkgconfdir.isDirectory())
		ipkgReady = true;
	} else
	    ipkgReady = ipkgconfdir.mkdirs();
    }

    private final void ipkgDirNotReady(ServiceMessage msg) throws LSException {
	msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "Fatal ipkg configuration failure");
    }

    /**
     * A function to make sure package names are safe
     * 
     * @param arg A package name to be passed to ipkg binary
     * @return True if package name is safe, false if not
     */
    private boolean checkArg(String arg) {
	String cleaned = arg.replaceAll("/[^A-Za-z0-9.-]/","");
	if (cleaned.equals(arg))
	    return true;
	else
	    return false;
    }

    private String readFile(File file, String delim) {
	StringBuilder contents = new StringBuilder();
	try { 
	    BufferedReader input =  new BufferedReader(new FileReader(file));
	    try {
		String line = null;
		while (( line = input.readLine()) != null){
		    contents.append(line);
		    contents.append(delim);
		}
	    } finally {
		input.close();
	    }
	} catch (IOException e){
	    System.err.println(e);
	}
	if (contents.length()>0)
	    return contents.toString();
	else
	    return null;
    }

    private JSONObject readList(File file, ServiceMessage msg, Boolean subscribe)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	int filesize = (int)file.length();
	int datasize = 0;
	int chunksize = 4096;
	int size = 0;
	if (!subscribe) {
	    chunksize = filesize;
	}
	char[] contents = new char[chunksize];
	if (subscribe) {
	    reply.put("stage", "start");
	    reply.put("filesize", filesize);
	    reply.put("chunksize", chunksize);
	    reply.put("returnValue",true);
	    msg.respond(reply.toString());
	    reply.remove("filesize");
	    reply.remove("chunksize");
	}
	try { 
	    FileReader fr = new FileReader(file);
	    try {
		if (subscribe) {
		    while ((size = fr.read(contents, 0, chunksize)) > 0) {
			reply.put("stage", "middle");
			reply.put("returnValue",true);
			reply.put("contents", new String(contents, 0, size));
			reply.put("size", size);
			msg.respond(reply.toString());
			datasize += size;
		    }
		}
		else {
		    size = fr.read(contents, 0, chunksize);
		    reply.put("returnValue",true);
		    reply.put("contents", new String(contents, 0, size));
		    reply.put("size", size);
		    datasize = size;
		}
	    }
	    finally {
		fr.close();
	    }
	} catch (IOException e){
	    System.err.println(e);
	    reply.put("returnValue",false);
	}
	if (subscribe) {
	    reply.put("stage", "end");
	    reply.put("datasize", datasize);
	    reply.remove("contents");
	    reply.remove("size");
	}
	return reply;
    }

    /**
     * A function to execute system commands.
     * 
     * @param command The system command to execute
     * @return A ReturnResult object containing the return value, stdout and stderr of
     * of the executed command.
     */
    private ReturnResult executeCMD(String command) {
	int ret = 1;
	ArrayList<String> output = new ArrayList<String>();
	ArrayList<String> errors = new ArrayList<String>();
	try {
	    ProcessBuilder builder = new ProcessBuilder(command.split(" "));
	    Map<String,String> env = builder.environment();
	    env.put("IPKG_OFFLINE_ROOT", "/var");
	    env.put("PKG_ROOT", "/");
	    Process p = builder.start();
	    InputStream stdout = p.getInputStream();
	    BufferedInputStream stdoutbuf = new BufferedInputStream(stdout);
	    InputStreamReader stdoutreader = new InputStreamReader(stdoutbuf);
	    BufferedReader bufferedstdoutreader = new BufferedReader(stdoutreader);
	    InputStream stderr = p.getErrorStream();
	    BufferedInputStream stderrbuf = new BufferedInputStream(stderr);
	    InputStreamReader stderrreader = new InputStreamReader(stderrbuf);
	    BufferedReader bufferedstderrreader = new BufferedReader(stderrreader);
	    
	    String line;
	    while ((line = bufferedstdoutreader.readLine()) != null) {
		output.add(line);
	    }
	    while ((line = bufferedstderrreader.readLine()) != null) {
		errors.add(line);
	    }
	    
	    try {
		if (p.waitFor() != 0) {
		    System.err.println("exit value = " + p.exitValue());
		    ret = p.exitValue();
		}
		else
		    ret = 0;
	    } catch (InterruptedException e) {
		System.err.println(e);
	    } finally {
		bufferedstdoutreader.close();
		stdoutreader.close();
		stdoutbuf.close();
		stdout.close();
		bufferedstderrreader.close();
		stderrreader.close();
		stderrbuf.close();
		stderr.close();
	    }
	} catch (IOException e) {
	    System.err.println(e.getMessage());
	}
	return new ReturnResult(ret, output, errors);
    }

    private JSONObject doGetConfigs()
	throws JSONException {
	JSONArray cfgs = new JSONArray();
	File[] configs = ipkgconfdir.listFiles();
	for (File file : configs) {
	    if (file.isFile()) {
		String filename = file.getName();
		if (!filename.equals("arch.conf")) {
		    JSONObject entry = new JSONObject();
		    if (filename.endsWith(".disabled")) {
			filename.replace(".disabled", "");
			entry.put("disabled", true);
		    }
		    entry.put(filename, readFile(file, "<br>"));
		    cfgs.put(entry);
		}
	    }
	}
	if (cfgs.length()>0) {
	    JSONObject reply = new JSONObject();
	    reply.put("configs",cfgs);
	    return reply;
	} else
	    return null;
    }

    private JSONObject doAddConfig(String config, String name, String url, Boolean gzip, ServiceMessage msg)
	throws JSONException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	File configfile = new File(ipkgConfigDirPath+"/"+config);
	reply.put("returnValue", true);
	if (!configfile.exists()) {
	    JSONObject parameters = new JSONObject();
	    JSONObject params =  new JSONObject();
	    String hash = idgen.nextSessionId();
	    params.put("config", config);
	    params.put("name", name);
	    params.put("url", url);
	    params.put("type", "add");
	    params.put("hash", hash);
	    parameters.put("id","org.webosinternals.ipkgservice");
	    parameters.put("params", params);
	    confirmations.put(hash, msg);
	    sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
	}
	return reply;
    }

    private JSONObject doDeleteConfig(String config, String name, String url, ServiceMessage msg)
	throws JSONException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	File configfile = new File(ipkgConfigDirPath+"/"+config);
	reply.put("returnValue", true);
	if (configfile.exists()) {
	    JSONObject parameters = new JSONObject();
	    JSONObject params =  new JSONObject();
	    String hash = idgen.nextSessionId();
	    params.put("config", config);
	    params.put("name", name);
	    params.put("url", url);
	    params.put("type", "delete");
	    params.put("hash", hash);
	    parameters.put("id","org.webosinternals.ipkgservice");
	    parameters.put("params", params);
	    confirmations.put(hash, msg);
	    sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
	}
	return reply;
    }

    private JSONObject doToggleConfigState(String configName)
	throws JSONException {
	JSONObject reply = new JSONObject();
	File config = new File(ipkgConfigDirPath+"/"+configName);
	Boolean status;
	if (configName.endsWith(".disabled"))
	    status = config.renameTo(new File(configName.replace(".disabled", "")));
	else
	    status = config.renameTo(new File(configName+".disabled"));
	reply.put("returnVal", status);
	reply.put("returnValue", status);
	return reply;
    }

    private JSONObject doUpdate(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD(ipkgBaseCommand + "update");
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'update' operation");
	}
	return reply;
    }
	
    public void confirmationLaunchCallback(ServiceMessage msg) {}

    private synchronized JSONObject doInstall(String packageName, String title, ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD(ipkgBaseCommand + "install " + packageName);
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stage","completed");
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	if (ret.returnValue==0) {
	    String postinstPath = ipkgScriptBasePath + packageName + ".postinst";
	    File postinst = new File(postinstPath);
	    if (postinst.exists()) {
		reply.put("stage","confirm");
		String script = readFile(postinst, "<br>");
		JSONObject parameters = new JSONObject();
		JSONObject params =  new JSONObject();
		String hash = idgen.nextSessionId();
		params.put("package", packageName);
		params.put("title", title);
		params.put("type", "install");
		params.put("script", script);
		params.put("hash", hash);
		parameters.put("id","org.webosinternals.ipkgservice");
		parameters.put("params", params);
		confirmations.put(hash, msg);
		sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
	    }
	} else {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'install' operation");
	}
	return reply;
    }

    private JSONObject doRemove(String packageName, String title, ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	String prermPath = ipkgScriptBasePath + packageName + ".prerm";
	File prerm = new File(prermPath);
	if (prerm.exists()) {
	    reply.put("returnVal", 0);
	    reply.put("returnValue", true);
	    reply.put("stage","confirm");
	    String script = readFile(prerm, "<br>");
	    JSONObject parameters = new JSONObject();
	    JSONObject params =  new JSONObject();
	    String hash = idgen.nextSessionId();
	    params.put("package", packageName);
	    params.put("title", title);
	    params.put("type", "remove");
	    params.put("script", script);
	    params.put("hash", hash);
	    parameters.put("id","org.webosinternals.ipkgservice");
	    parameters.put("params", params);
	    confirmations.put(hash, msg);
	    sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
	} else {
	    ReturnResult ret = executeCMD(ipkgBaseCommand + "remove " + packageName);
	    reply.put("returnVal",ret.returnValue);
	    reply.put("returnValue",(ret.returnValue == 0));
	    reply.put("stage","completed");
	    reply.put("stdOut", ret.stdOut);
	    reply.put("stdErr", ret.stdErr);
	    if (ret.returnValue!=0) {
		reply.put("stage","failed");
		reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
		reply.put("errorText", "Failure during 'remove' operation");
	    }
	}
	return reply;
    }
   
    private JSONObject doRescan(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("luna-send -n 1 palm://com.palm.applicationManager/rescan {}");
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'rescan' operation");
	}
	return reply;
    }

    private JSONObject doRestartLuna(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("killall -HUP LunaSysMgr");
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartluna' operation");
	}
	return reply;
    }

    private JSONObject doRestartJava(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("killall java");
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartjava' operation");
	}
	return reply;
    }

    private JSONObject getRawList(String feedName, ServiceMessage msg, Boolean subscribe)
	throws JSONException, LSException {
	String filename = ipkgListsBasePath + feedName;
	File listfile = new File(filename);
	if (listfile.exists()) {
	    return readList(listfile, msg, subscribe);
	} else
	    return null;
    }

    private JSONObject getRawStatus(ServiceMessage msg)
	throws JSONException, LSException {
	String filename = ipkgStatusPath;
	File statusfile = new File(filename);
	if (statusfile.exists()) {
	    return readList(statusfile, msg, false);
	} else
	    return null;
    }

    /* ============================ DBUS Methods =============================*/

    @LunaServiceThread.PublicMethod
	public void install(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("package")) {
		String pkg = msg.getJSONPayload().getString("package").trim();
		String title = msg.getJSONPayload().getString("title").trim();
		if (checkArg(pkg)) {
		    JSONObject reply = doInstall(pkg, title, msg);
		    msg.respond(reply.toString());
		}
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'package' parameter");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void remove(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("package")) {
		String pkg = msg.getJSONPayload().getString("package").trim();
		String title = msg.getJSONPayload().getString("title").trim();
		if (checkArg(pkg)) {
		    JSONObject reply = doRemove(pkg, title, msg);
		    msg.respond(reply.toString());
		}
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'package' parameter");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void update(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doUpdate(msg);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void rescan(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRescan(msg);
	msg.respond(reply.toString());
    }

    @LunaServiceThread.PublicMethod
	public void restartLuna(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRestartLuna(msg);
	msg.respond(reply.toString());
    }

    @LunaServiceThread.PublicMethod
	public void restartJava(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRestartJava(msg);
	msg.respond(reply.toString());
    }

    @LunaServiceThread.PublicMethod
	public void getConfigs(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doGetConfigs();
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'getConfigs' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void addConfig(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config") &&
		msg.getJSONPayload().has("name") &&
		msg.getJSONPayload().has("url") &&
		msg.getJSONPayload().has("gzip")) {
		JSONObject reply = doAddConfig(msg.getJSONPayload().getString("config").trim(),
					       msg.getJSONPayload().getString("name").trim(),
					       msg.getJSONPayload().getString("url").trim(),
					       msg.getJSONPayload().getBoolean("gzip"),
					       msg);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'addConfig' operation");
	    }
	    else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'config', 'name', 'url' or 'gzip' parameter");
	    }
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void deleteConfig(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config") &&
		msg.getJSONPayload().has("name") &&
		msg.getJSONPayload().has("url")) {
		JSONObject reply = doDeleteConfig(msg.getJSONPayload().getString("config").trim(),
						  msg.getJSONPayload().getString("name").trim(),
						  msg.getJSONPayload().getString("url").trim(),
						  msg);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'deleteConfig' operation");
	    }
	    else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'config', 'name' or 'url' parameter");
	    }
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void toggleConfigState(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config")) {
		msg.respond(doToggleConfigState(msg.getJSONPayload().getString("config").trim()).toString());
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'config' parameter");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void confirmInstall(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret;
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("hash") && msg.getJSONPayload().has("confirmation")) {
		String hash = msg.getJSONPayload().getString("hash");
		ServiceMessage origmsg = confirmations.get(hash);
		boolean confirmation = msg.getJSONPayload().getBoolean("confirmation");
		if (origmsg!=null) {
		    reply.put("returnVal",0);
		    reply.put("returnValue",true);
		    msg.respond(reply.toString());
		    if (confirmation) {
			if (origmsg.getJSONPayload().has("package")) {
			    String pkg = origmsg.getJSONPayload().getString("package").trim();
			    if (checkArg(pkg)) {
				String postinstPath = ipkgScriptBasePath + pkg + ".postinst";
				File postinst = new File(postinstPath);
				if (postinst.exists()) {
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("returnValue",true);
					reply.put("stage","unlock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,rw /");
					reply.put("returnVal",ret.returnValue);
					reply.put("returnValue",(ret.returnValue == 0));
					reply.put("stdOut", ret.stdOut);
					reply.put("stdErr", ret.stdErr);
					if (ret.returnValue!=0) {
					    reply.put("stage","failed");
					    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					    reply.put("errorText", "Failure during 'remount' operation");
					    origmsg.respond(reply.toString());
					    return;
					}
				    }
				    reply.put("stage","postinst");
				    origmsg.respond(reply.toString());
				    ret = executeCMD(postinstPath);
				    reply.put("stdOut", ret.stdOut);
				    reply.put("stdErr", ret.stdErr);
				    reply.put("returnVal",ret.returnValue);
				    reply.put("returnValue",(ret.returnValue == 0));
				    if (ret.returnValue!=0) {
					reply.put("stage","failed");
					reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					reply.put("errorText", "Failure during 'postinst' operation");
					origmsg.respond(reply.toString());
					return;
				    }
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("returnValue",true);
					reply.put("stage","lock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,ro /");
					reply.put("returnVal",ret.returnValue);
					reply.put("returnValue",(ret.returnValue == 0));
					reply.put("stdOut", ret.stdOut);
					reply.put("stdErr", ret.stdErr);
					if (ret.returnValue!=0) {
					    reply.put("stage","failed");
					    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					    reply.put("errorText", "Failure during 'remount' operation");
					    origmsg.respond(reply.toString());
					    return;
					}
				    }
				    reply.put("stage","completed");
				    origmsg.respond(reply.toString());
				    return;
				} else {
				    origmsg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
						     "Internal error: Missing 'postinst' file");
				    return;
				}
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'package' parameter");
				return;
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'package' parameter");
			    return;
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled post install script execution");
			origmsg.respond(reply.toString());
			return;
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		    return;
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
		return;
	    }
	} else {
	    ipkgDirNotReady(msg);
	    return;
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmRemove(ServiceMessage msg)
	throws JSONException, LSException {
	ReturnResult ret;
	JSONObject reply = new JSONObject();
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("hash") && msg.getJSONPayload().has("confirmation")) {
		String hash = msg.getJSONPayload().getString("hash");
		ServiceMessage origmsg = confirmations.get(hash);
		boolean confirmation = msg.getJSONPayload().getBoolean("confirmation");
		if (origmsg!=null) {
		    reply.put("returnVal",0);
		    reply.put("returnValue",true);
		    msg.respond(reply.toString());
		    if (confirmation) {
			if (origmsg.getJSONPayload().has("package")) {
			    String pkg = origmsg.getJSONPayload().getString("package").trim();
			    if (checkArg(pkg)) {
				String prermPath = ipkgScriptBasePath + pkg + ".prerm";
				File prerm = new File(prermPath);
				if (prerm.exists()) {
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("returnValue",true);
					reply.put("stage","unlock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,rw /");
					reply.put("returnVal",ret.returnValue);
					reply.put("returnValue",(ret.returnValue == 0));
					reply.put("stdOut", ret.stdOut);
					reply.put("stdErr", ret.stdErr);
					if (ret.returnValue!=0) {
					    reply.put("stage","failed");
					    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					    reply.put("errorText", "Failure during 'remount' operation");
					    origmsg.respond(reply.toString());
					    return;
					}
				    }
				    reply.put("stage","prerm");
				    origmsg.respond(reply.toString());
				    ret = executeCMD(prermPath);
				    reply.put("stdOut", ret.stdOut);
				    reply.put("stdErr", ret.stdErr);
				    reply.put("returnVal",ret.returnValue);
				    reply.put("returnValue",(ret.returnValue == 0));
				    if (ret.returnValue!=0) {
					reply.put("stage","failed");
					reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					reply.put("errorText", "Failure during 'prerm' operation");
					origmsg.respond(reply.toString());
					return;
				    }
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("returnValue",true);
					reply.put("stage","lock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,ro /");
					reply.put("returnVal",ret.returnValue);
					reply.put("returnValue",(ret.returnValue == 0));
					reply.put("stdOut", ret.stdOut);
					reply.put("stdErr", ret.stdErr);
					if (ret.returnValue!=0) {
					    reply.put("stage","failed");
					    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					    reply.put("errorText", "Failure during 'remount' operation");
					    origmsg.respond(reply.toString());
					    return;
					}
				    }
				    reply.put("stage","remove");
				    origmsg.respond(reply.toString());
				    // pass-through
				} else {
				    origmsg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
							 "Internal error: Missing 'prerm' file");
				    return;
				}
				ret = executeCMD(ipkgBaseCommand + "remove " + pkg);
				reply.put("returnVal",ret.returnValue);
				reply.put("returnValue",(ret.returnValue == 0));
				reply.put("stdOut", ret.stdOut);
				reply.put("stdErr", ret.stdErr);
				if (ret.returnValue!=0) {
				    reply.put("stage","failed");
				    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
				    reply.put("errorText", "Failure during 'remove' operation");
				    origmsg.respond(reply.toString());
				    return;
				} else {
				    reply.put("stage","completed");
				    origmsg.respond(reply.toString());
				    return;
				}
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'package' parameter");
				return;
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'package' parameter");
			    return;
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled pre remove script execution");
			origmsg.respond(reply.toString());
			return;
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		    return;
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
		return;
	    }
	} else {
	    ipkgDirNotReady(msg);
	    return;
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmAdd(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret;
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("hash") && msg.getJSONPayload().has("confirmation")) {
		String hash = msg.getJSONPayload().getString("hash");
		ServiceMessage origmsg = confirmations.get(hash);
		boolean confirmation = msg.getJSONPayload().getBoolean("confirmation");
		if (origmsg!=null) {
		    reply.put("returnVal",0);
		    reply.put("returnValue",true);
		    msg.respond(reply.toString());
		    if (confirmation) {
			if (origmsg.getJSONPayload().has("config")) {
			    String config = origmsg.getJSONPayload().getString("config").trim();
			    if (checkArg(config)) {
				reply.put("stage","completed");
				origmsg.respond(reply.toString());
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'config' parameter");
				return;
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'config' parameter");
			    return;
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled feed config addition");
			origmsg.respond(reply.toString());
			return;
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		    return;
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
		return;
	    }
	} else {
	    ipkgDirNotReady(msg);
	    return;
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmDelete(ServiceMessage msg)
	throws JSONException, LSException {
	ReturnResult ret;
	JSONObject reply = new JSONObject();
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("hash") && msg.getJSONPayload().has("confirmation")) {
		String hash = msg.getJSONPayload().getString("hash");
		ServiceMessage origmsg = confirmations.get(hash);
		boolean confirmation = msg.getJSONPayload().getBoolean("confirmation");
		if (origmsg!=null) {
		    reply.put("returnVal",0);
		    reply.put("returnValue",true);
		    msg.respond(reply.toString());
		    if (confirmation) {
			if (origmsg.getJSONPayload().has("config")) {
			    String config = origmsg.getJSONPayload().getString("config").trim();
			    if (checkArg(config)) {
				reply.put("stage","completed");
				origmsg.respond(reply.toString());
				return;
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'config' parameter");
				return;
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'config' parameter");
			    return;
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled feed config deletion");
			origmsg.respond(reply.toString());
			return;
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		    return;
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
		return;
	    }
	} else {
	    ipkgDirNotReady(msg);
	    return;
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void getListFile(ServiceMessage msg)
	throws JSONException, LSException {
	Boolean subscribe = false;
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("subscribe") && msg.getJSONPayload().getBoolean("subscribe")) {
		subscribe = true;
	    }
	    if (msg.getJSONPayload().has("feed")) {
		JSONObject reply = getRawList(msg.getJSONPayload().getString("feed").trim(), msg, subscribe);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'getListFile' operation");
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'feed' parameter");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void getStatusFile(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getRawStatus(msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'getStatusFile' operation");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void status(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = new JSONObject();
	    reply.put("returnValue",true);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void version(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	reply.put("returnValue",true);
	reply.put("apiVersion","5");
	msg.respond(reply.toString());
    }


    /* ============================ Deprecated Method Names =============================*/

    @LunaServiceThread.PublicMethod
	public void rawlist(ServiceMessage msg)
	throws JSONException, LSException {
	Boolean subscribe = false;
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("subscribe") && msg.getJSONPayload().getBoolean("subscribe")) {
		subscribe = true;
	    }
	    if (msg.getJSONPayload().has("feed")) {
		JSONObject reply = getRawList(msg.getJSONPayload().getString("feed").trim(), msg, subscribe);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'raw list' operation");
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'feed' parameter");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void rawstatus(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getRawStatus(msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'raw status' operation");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void restartluna(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRestartLuna(msg);
	msg.respond(reply.toString());
    }

    @LunaServiceThread.PublicMethod
	public void restartjava(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRestartJava(msg);
	msg.respond(reply.toString());
    }

    @LunaServiceThread.PublicMethod
	public void list_configs(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doGetConfigs();
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'list configs' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void toggle_config(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config")) {
		msg.respond(doToggleConfigState(msg.getJSONPayload().getString("config").trim()).toString());
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'config' parameter");
	} else
	    ipkgDirNotReady(msg);
    }
	
}

