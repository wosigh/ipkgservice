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
    private String ipkgBaseCommand;
    private String ipkgOfflineRoot;
    private String ipkgConfigDirPath;
    private String ipkgScriptBasePath;
    private String ipkgListsBasePath;
    private String ipkgStatusPath;
    private String ipkgApplicationBasePath;

    private File ipkgconfdir;
    private boolean ipkgReady = false;
    private boolean isEmulator = false;
    private boolean isCryptofs = false;
    private SessionIDGenerator idgen = new SessionIDGenerator();
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
	File lunaconf = new File("/etc/palm/luna.conf");
	isCryptofs = readFile(lunaconf, " ").contains("/media/cryptofs/apps");
	String tmpdirPath;
	if (isCryptofs) {
	    tmpdirPath = "/media/cryptofs/apps/usr/lib/ipkg/tmp";
	    ipkgBaseCommand = "/usr/bin/ipkg --tmp-dir " + tmpdirPath + " -o /media/cryptofs/apps ";
	    ipkgOfflineRoot = "/media/cryptofs/apps";
	    ipkgConfigDirPath = "/media/cryptofs/apps/etc/ipkg";
	    ipkgScriptBasePath = "/media/cryptofs/apps/usr/lib/ipkg/info/";
	    ipkgListsBasePath = "/media/cryptofs/apps/usr/lib/ipkg/lists/";
	    ipkgStatusPath = "/media/cryptofs/apps/usr/lib/ipkg/status";
	    ipkgApplicationBasePath = "/media/cryptofs/apps/usr/palm/applications/";
	}
	else {
	    tmpdirPath = "/var/usr/lib/ipkg/tmp";
	    ipkgBaseCommand = "/usr/bin/ipkg --tmp-dir " + tmpdirPath + " -o /var ";
	    ipkgOfflineRoot = "/var";
	    ipkgConfigDirPath = "/var/etc/ipkg";
	    ipkgScriptBasePath = "/var/usr/lib/ipkg/info/";
	    ipkgListsBasePath = "/var/usr/lib/ipkg/lists/";
	    ipkgStatusPath = "/var/usr/lib/ipkg/status";
	    ipkgApplicationBasePath = "/var/usr/palm/applications/";
	}
	ipkgconfdir = new File(ipkgConfigDirPath);
	if (ipkgconfdir.exists()) {
	    if (ipkgconfdir.isDirectory())
		ipkgReady = true;
	} else
	    ipkgReady = ipkgconfdir.mkdirs();

	File tmpdir = new File(tmpdirPath);
	if (tmpdir.exists()) {
		if (! tmpdir.isDirectory()) {
			tmpdir.delete();
			tmpdir.mkdirs();
		}
	}
	else {
		tmpdir.mkdirs();
	}
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
	if (filesize > 10485760) {
	    reply.put("stage", "failed");
	    reply.put("filesize", filesize);
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Requested feed listing is too large");
	    reply.put("returnValue",false);
	    return reply;
	}
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
    private ReturnResult executeCMD(String command, Boolean redirectErrorStream, ServiceMessage msg) 
	throws JSONException, LSException {
	int ret = 1;
	Boolean override = false;
	JSONObject reply = new JSONObject();
	ArrayList<String> output = new ArrayList<String>();
	ArrayList<String> errors = new ArrayList<String>();
	try {
	    ProcessBuilder builder = new ProcessBuilder(command.split(" "));
	    builder.redirectErrorStream(redirectErrorStream);
	    Map<String,String> env = builder.environment();
	    env.put("IPKG_OFFLINE_ROOT", ipkgOfflineRoot);
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
		if (line.startsWith("Collected errors:") ||
		    line.startsWith("ipkg_download: ERROR:")) {
		    errors.add(line);
		    override = true;
		}
		else {
		    output.add(line);
		}
		if (msg != null) {
		    if (line.startsWith("Downloading ")) {
			reply.put("returnValue",true);
			reply.put("stage","status");
			reply.put("status", line);
			msg.respond(reply.toString());
		    }
		    else if (line.startsWith("Configuring ")) {
			reply.put("returnValue",true);
			reply.put("stage","status");
			reply.put("status", line);
			msg.respond(reply.toString());
		    }
		    else if (line.startsWith("Removing ")) {
			reply.put("returnValue",true);
			reply.put("stage","status");
			reply.put("status", line);
			msg.respond(reply.toString());
		    }
		}
	    }
	    while ((line = bufferedstderrreader.readLine()) != null) {
		errors.add(line);
	    }
	    
	    try {
		if (p.waitFor() != 0) {
		    System.err.println("exit value = " + p.exitValue());
		    ret = p.exitValue();
		}
		else {
		    ret = 0;
		}
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

	if (override) ret = 1;

	return new ReturnResult(ret, output, errors);
    }

    private Boolean unlockRootfs(ServiceMessage msg)
	throws JSONException, LSException {
	if (isEmulator) return true;
	ReturnResult ret = executeCMD("/bin/mount -o remount,rw /", false, null);
	if (msg != null) {
	    JSONObject reply = new JSONObject();
	    reply.put("returnVal",ret.returnValue);
	    reply.put("returnValue",(ret.returnValue == 0));
	    reply.put("stage","unlock");
	    reply.put("stdOut", ret.stdOut);
	    reply.put("stdErr", ret.stdErr);
	    msg.respond(reply.toString());
	}
	return (ret.returnValue == 0);
    }
	
    private Boolean lockRootfs(ServiceMessage msg)
	throws JSONException, LSException {
	if (isEmulator) return true;
	ReturnResult ret = executeCMD("/bin/mount -o remount,ro /", false, null);
	if (msg != null) {
	    JSONObject reply = new JSONObject();
	    reply.put("returnVal",ret.returnValue);
	    reply.put("returnValue",(ret.returnValue == 0));
	    reply.put("stage","lock");
	    reply.put("stdOut", ret.stdOut);
	    reply.put("stdErr", ret.stdErr);
	    msg.respond(reply.toString());
	}
	return (ret.returnValue == 0);
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
		    Boolean enabled = true;
		    if (filename.endsWith(".disabled")) {
			filename = filename.substring(0, filename.lastIndexOf(".disabled"));
			enabled = false;
		    }
		    entry.put("config", filename);
		    entry.put("contents", readFile(file, "<br>"));
		    entry.put("enabled", enabled);
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

    private JSONObject doSetConfigState(String configName, Boolean enabled)
	throws JSONException {
	JSONObject reply = new JSONObject();
	Boolean status;
	if (enabled) {
	    File config = new File(ipkgConfigDirPath+"/"+configName+".disabled");
	    status = config.renameTo(new File(ipkgConfigDirPath+"/"+configName));
	}
	else {
	    File config = new File(ipkgConfigDirPath+"/"+configName);
	    status = config.renameTo(new File(ipkgConfigDirPath+"/"+configName+".disabled"));
	}
	reply.put("returnValue", status);
	return reply;
    }

    private JSONObject doUpdate(ServiceMessage msg, Boolean subscribe)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret;
	if (subscribe) {
	    reply.put("stage", "update");
	    reply.put("returnValue",true);
	    msg.respond(reply.toString());
	    ret = executeCMD(ipkgBaseCommand + "update", false, msg);
	}
	else {
	    ret = executeCMD(ipkgBaseCommand + "update", false, null);
	}
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'update' operation");
	    reply.put("stage","failed");
	}
	else {
	    reply.put("stage","completed");
	}
	return reply;
    }
	
    public void confirmationLaunchCallback(ServiceMessage msg) {}

    private Boolean executePostinst(String pkg, String postinstPath, ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret;
	if (!unlockRootfs(msg)) {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'remount' operation");
	    msg.respond(reply.toString());
	    return false;
	}
	ret = executeCMD(postinstPath, false, msg);
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stage","postinst");
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	msg.respond(reply.toString());
	reply.remove("stdOut");
	reply.remove("stdErr");
	if (!lockRootfs(msg)) {
	    // We're going to ignore failures from the remount
	}
	if (ret.returnValue!=0) {
	    // Remove the remnants of any package which was not installed properly
	    ret = executeCMD(ipkgBaseCommand + "remove " + pkg, false, msg);
	    reply.put("returnVal",ret.returnValue);
	    reply.put("returnValue",(ret.returnValue == 0));
	    reply.put("stage","remove");
	    reply.put("stdOut", ret.stdOut);
	    reply.put("stdErr", ret.stdErr);
	    msg.respond(reply.toString());
	    reply.remove("stdOut");
	    reply.remove("stdErr");
	    reply.put("returnVal",1);
	    reply.put("returnValue",false);
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during post-install script execution");
	    msg.respond(reply.toString());
	    return false;
	}
	return true;
    }

    private synchronized void doInstall(String packageName, String title, ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD(ipkgBaseCommand + "install " + packageName, false, msg);
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stage","install");
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	msg.respond(reply.toString());
	reply.remove("stdOut");
	reply.remove("stdErr");
	if (ret.returnValue==0) {
	    String postinstPath = ipkgScriptBasePath + packageName + ".postinst";
	    File postinst = new File(postinstPath);
	    if (postinst.exists()) {
		Boolean signed = false;
		String signaturePath = postinstPath + ".sha1";
		File signature = new File(signaturePath);
		// %%% Check for signature %%%
		signed = signature.exists(); // %% Remove this %%%
		// %%% Check for signature %%%
		if (signed) {
		    Boolean valid = false;
		    // %%% Check if signature is valid %%%
		    valid = true; // %% Remove this %%%
		    // %%% Check if signature is valid %%%
		    if (valid) {
			if (executePostinst(packageName, postinstPath, msg)) {
			    reply.put("stage","completed");
			    msg.respond(reply.toString());
			}
		    }
		    else {
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText", "Signature verification failed during 'install' operation");
			msg.respond(reply.toString());
		    }
		}
		else {
		    reply.put("stage","confirm");
		    reply.append("stdOut", "User consent requested for post-install script execution");
		    msg.respond(reply.toString());
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
	    }
	    else {
		reply.put("stage","completed");
		msg.respond(reply.toString());
	    }
	} else {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'install' operation");
	    msg.respond(reply.toString());
	}
    }

    private Boolean executePrerm(String pkg, String prermPath, ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret;
	if (!unlockRootfs(msg)) {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'remount' operation");
	    msg.respond(reply.toString());
	    return false;
	}
	ret = executeCMD(prermPath, false, msg);
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stage","prerm");
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	msg.respond(reply.toString());
	reply.remove("stdOut");
	reply.remove("stdErr");
	if (!lockRootfs(msg)) {
	    // We're going to ignore failures from the remount
	}
	if (ret.returnValue!=0) {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during pre-remove script execution");
	    msg.respond(reply.toString());
	    return false;
	}
	return true;
    }

    private synchronized void doRemove(String packageName, String title, Boolean replace, ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	JSONObject reply = new JSONObject();
	String prermPath = ipkgScriptBasePath + packageName + ".prerm";
	File prerm = new File(prermPath);
	if (prerm.exists()) {
	    Boolean signed = false;
	    String signaturePath = prermPath + ".sha1";
	    File signature = new File(signaturePath);
	    // %%% Check for signature %%%
	    signed = signature.exists(); // %% Remove this %%%
	    // %%% Check for signature %%%
	    if (signed) {
		Boolean valid = false;
		// %%% Check if signature is valid %%%
		valid = true; // %% Remove this %%%
		// %%% Check if signature is valid %%%
		if (valid) {
		    if (!executePrerm(packageName, prermPath, msg)) {
			return;
		    }
		    // pass-through
		}
		else {
		    reply.put("stage","failed");
		    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
		    reply.put("errorText", "Signature verification failed during 'remove' operation");
		    msg.respond(reply.toString());
		    return;
		}
	    }
	    else {
		reply.put("returnVal", 0);
		reply.put("returnValue", true);
		reply.put("stage","confirm");
		reply.append("stdOut", "User consent requested for pre-remove script execution");
		msg.respond(reply.toString());
		String script = readFile(prerm, "<br>");
		JSONObject parameters = new JSONObject();
		JSONObject params =  new JSONObject();
		String hash = idgen.nextSessionId();
		params.put("package", packageName);
		params.put("title", title);
		if (replace) {
		    params.put("type", "replace");
		}
		else {
		    params.put("type", "remove");
		}
		params.put("script", script);
		params.put("hash", hash);
		parameters.put("id","org.webosinternals.ipkgservice");
		parameters.put("params", params);
		confirmations.put(hash, msg);
		sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
		return;
	    }
	}
	ReturnResult ret = executeCMD(ipkgBaseCommand + "remove " + packageName, false, msg);
	reply.put("returnVal",ret.returnValue);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stage","remove");
	reply.put("stdOut", ret.stdOut);
	reply.put("stdErr", ret.stdErr);
	msg.respond(reply.toString());
	reply.remove("stdOut");
	reply.remove("stdErr");
	if (ret.returnValue!=0) {
	    reply.put("stage","failed");
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'remove' operation");
	    msg.respond(reply.toString());
	}
	else if (replace) {
	    doInstall(packageName, title, msg);
	}
	else {
	    reply.put("stage","completed");
	    msg.respond(reply.toString());
	}
    }
   
    private JSONObject doRescan(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("luna-send -n 1 palm://com.palm.applicationManager/rescan {}", false, null);
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
	ReturnResult ret = executeCMD("killall -HUP LunaSysMgr", false, null);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartLuna' operation");
	}
	return reply;
    }

    private JSONObject doRestartJava(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("killall java", false, null);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartJava' operation");
	}
	return reply;
    }

    private JSONObject doRestartDevice(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("tellbootie", false, null);
	reply.put("returnValue",(ret.returnValue == 0));
	reply.put("stdOut", ret.stdOut.toString());
	reply.put("stdErr", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartDevice' operation");
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

    private JSONObject getRawControl(String packageId, ServiceMessage msg)
	throws JSONException, LSException {
	String filename = ipkgScriptBasePath + packageId + ".control";
	File controlfile = new File(filename);
	if (controlfile.exists()) {
	    return readList(controlfile, msg, false);
	} else
	    return null;
    }

    private JSONObject getRawAppinfo(String packageId, ServiceMessage msg)
	throws JSONException, LSException {
	String filename = ipkgApplicationBasePath + packageId + "/appinfo.json";
	File appinfofile = new File(filename);
	if (appinfofile.exists()) {
	    return readList(appinfofile, msg, false);
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
		    doInstall(pkg, title, msg);
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
		    doRemove(pkg, title, false, msg);
		}
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'package' parameter");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void replace(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("package")) {
		String pkg = msg.getJSONPayload().getString("package").trim();
		String title = msg.getJSONPayload().getString("title").trim();
		if (checkArg(pkg)) {
		    doRemove(pkg, title, true, msg);
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
	Boolean subscribe = false;
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("subscribe") && msg.getJSONPayload().getBoolean("subscribe")) {
		subscribe = true;
	    }
	    JSONObject reply = doUpdate(msg, subscribe);
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
	public void restartDevice(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = doRestartDevice(msg);
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
	public void setConfigState(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config") && msg.getJSONPayload().has("enabled")) {
		msg.respond(doSetConfigState(msg.getJSONPayload().getString("config").trim(), msg.getJSONPayload().getBoolean("enabled")).toString());
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'config' or 'enabled' parameter");
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
			reply.put("returnVal", 0);
			reply.put("returnValue", true);
			reply.put("stage","approve");
			reply.append("stdOut", "User approved post-install script execution");
			origmsg.respond(reply.toString());
			if (origmsg.getJSONPayload().has("package")) {
			    String pkg = origmsg.getJSONPayload().getString("package").trim();
			    if (checkArg(pkg)) {
				String postinstPath = ipkgScriptBasePath + pkg + ".postinst";
				File postinst = new File(postinstPath);
				if (postinst.exists()) {
				    if (executePostinst(pkg, postinstPath, origmsg)) {
					reply.put("stage","completed");
					origmsg.respond(reply.toString());
				    }
				} else {
				    origmsg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
							 "Internal error: Missing 'postinst' file");
				}
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'package' parameter");
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'package' parameter");
			}
		    } else {
			reply.put("returnVal", 1);
			reply.put("returnValue", false);
			reply.put("stage","cancel");
			reply.append("stdErr", "User cancelled post-install script execution");
			origmsg.respond(reply.toString());
			if (origmsg.getJSONPayload().has("package")) {
			    String pkg = origmsg.getJSONPayload().getString("package").trim();
			    if (checkArg(pkg)) {
				// Remove the remnants of any package which was not installed properly
				ret = executeCMD(ipkgBaseCommand + "remove " + pkg, false, origmsg);
				reply.put("returnVal",ret.returnValue);
				reply.put("returnValue",(ret.returnValue == 0));
				reply.put("stage","remove");
				reply.put("stdOut", ret.stdOut);
				reply.put("stdErr", ret.stdErr);
				origmsg.respond(reply.toString());
				reply.remove("stdOut");
				reply.remove("stdErr");
				reply.put("returnVal",1);
				reply.put("returnValue",false);
				reply.put("stage","failed");
				reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
				reply.put("errorText","User cancelled post-install script execution");
				origmsg.respond(reply.toString());
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'package' parameter");
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'package' parameter");
			}
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
	    }
	} else {
	    ipkgDirNotReady(msg);
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmRemove(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
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
			reply.put("returnVal", 0);
			reply.put("returnValue", true);
			reply.put("stage","approve");
			reply.append("stdOut", "User approved pre-remove script execution");
			if (origmsg.getJSONPayload().has("package")) {
			    String pkg = origmsg.getJSONPayload().getString("package").trim();
			    if (checkArg(pkg)) {
				String prermPath = ipkgScriptBasePath + pkg + ".prerm";
				File prerm = new File(prermPath);
				if (prerm.exists()) {
				    if (!executePrerm(pkg, prermPath, origmsg)) {
					return;
				    }
				    // pass-through
				} else {
				    origmsg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
							 "Internal error: Missing 'prerm' file");
				    return;
				}
				ret = executeCMD(ipkgBaseCommand + "remove " + pkg, false, origmsg);
				reply.put("returnVal",ret.returnValue);
				reply.put("returnValue",(ret.returnValue == 0));
				reply.put("stage","remove");
				reply.put("stdOut", ret.stdOut);
				reply.put("stdErr", ret.stdErr);
				origmsg.respond(reply.toString());
				reply.remove("stdOut");
				reply.remove("stdErr");
				String title = origmsg.getJSONPayload().getString("title");
				Boolean replace = msg.getJSONPayload().getBoolean("replace");
				if (ret.returnValue!=0) {
				    reply.put("stage","failed");
				    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
				    reply.put("errorText", "Failure during 'remove' operation");
				    origmsg.respond(reply.toString());
				} else if (replace) {
				    doInstall(pkg, title, origmsg);
				} else {
				    reply.put("stage","completed");
				    origmsg.respond(reply.toString());
				}
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'package' parameter");
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'package' parameter");
			}
		    } else {
			reply.put("returnVal", 1);
			reply.put("returnValue", false);
			reply.put("stage","cancel");
			reply.append("stdErr", "User cancelled pre-remove script execution");
			origmsg.respond(reply.toString());
			reply.remove("stdErr");
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled pre-remove script execution");
			origmsg.respond(reply.toString());
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
	    }
	} else {
	    ipkgDirNotReady(msg);
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmAdd(ServiceMessage msg)
	throws JSONException, LSException {
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
				// DO STUFF HERE
				reply.put("stage","completed");
				origmsg.respond(reply.toString());
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'config' parameter");
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'config' parameter");
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled feed config addition");
			origmsg.respond(reply.toString());
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
	    }
	} else {
	    ipkgDirNotReady(msg);
	}
    }
    
    @LunaServiceThread.PublicMethod
	public void confirmDelete(ServiceMessage msg)
	throws JSONException, LSException {
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
				// DO STUFF HERE
				reply.put("stage","completed");
				origmsg.respond(reply.toString());
			    } else {
				origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						     "Invalid 'config' parameter");
			    }
			} else {
			    origmsg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
						 "Missing 'config' parameter");
			}
		    } else {
			reply.put("returnVal",1);
			reply.put("returnValue",false);
			reply.put("stage","failed");
			reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
			reply.put("errorText","User cancelled feed config deletion");
			origmsg.respond(reply.toString());
		    }
		} else {
		    msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				     "Invalid 'hash' parameter");
		}
	    } else {
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'hash' or 'confirmation' parameter");
	    }
	} else {
	    ipkgDirNotReady(msg);
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
	public void getControlFile(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("package")) {
		JSONObject reply = getRawControl(msg.getJSONPayload().getString("package").trim(), msg);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'getControlFile' operation");
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'package' parameter");
	} else
	    ipkgDirNotReady(msg);
    }
	
    @LunaServiceThread.PublicMethod
	public void getAppinfoFile(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("package")) {
		JSONObject reply = getRawAppinfo(msg.getJSONPayload().getString("package").trim(), msg);
		if (reply!=null)
		    msg.respond(reply.toString());
		else
		    msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				     "Failure during 'getAppinfoFile' operation");
	    } else
		msg.respondError(ErrorMessage.ERROR_CODE_INVALID_PARAMETER,
				 "Missing 'package' parameter");
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
	reply.put("apiVersion","10");
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

    private JSONObject doListConfigs()
	throws JSONException {
	JSONArray cfgs = new JSONArray();
	File[] configs = ipkgconfdir.listFiles();
	for (File file : configs) {
	    if (file.isFile()) {
		String filename = file.getName();
		if (!filename.equals("arch.conf")) {
		    JSONObject entry = new JSONObject();
		    if (!filename.endsWith(".disabled")) {
			entry.put(filename, readFile(file, "<br>"));
			cfgs.put(entry);
		    }
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

    @LunaServiceThread.PublicMethod
	public void list_configs(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doListConfigs();
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'list configs' operation");
	} else
	    ipkgDirNotReady(msg);
    }

}

