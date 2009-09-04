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
import java.util.Iterator;
import java.util.LinkedHashSet;

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

    private Runtime runtime;
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
	if (ipkgReady)
	    runtime = Runtime.getRuntime();
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

    /**
     * Compare version strings
     * 
     * @param version1
     * @param version2
     * @return 1 is version1 is larger, -1 if version1 is smaller, 0 if equal
     */
    private int compareVersions(String[] version1, String[] version2) {
	int ret = 0;
	int val1 = Integer.valueOf(version1[0]);
	int val2 = Integer.valueOf(version2[0]);
	if ( val1 > val2 ) {
	    ret = 1;
	} else if ( val1 < val2 ) {		
	    ret = -1;
	} else if ( val1 == val2 ) {
	    val1 = Integer.valueOf(version1[1]);
	    val2 = Integer.valueOf(version2[1]);
	    if ( val1 > val2 ) {
		ret = 1;
	    } else if ( val1 < val2 ) {
		ret = -1;
	    } else if ( val1 == val2 ) {
		val1 = Integer.valueOf(version1[2]);
		val2 = Integer.valueOf(version2[2]);
		if ( val1 > val2 ) {
		    ret = 1;
		} else if ( val1 < val2 ) {
		    ret = -1;
		}
	    }
	}
	return ret;
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
	if (checkArg(command)) {
	    try {
		Process p = runtime.exec(command);
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
		    if (p.waitFor() != 0)
			System.err.println("exit value = " + p.exitValue());
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
	}
	return new ReturnResult(ret, output, errors);
    }

    private JSONObject getConfigs()
	throws JSONException {
	JSONArray cfgs = new JSONArray();
	File[] configs = ipkgconfdir.listFiles();
	for (File file : configs) {
	    if (file.isFile()) {
		String filename = file.getName();
		if (!filename.equals("arch.conf")) {
		    JSONObject entry = new JSONObject();
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

    private JSONObject toggleConfigState(String configName)
	throws JSONException {
	JSONObject result = new JSONObject();
	File config = new File(ipkgConfigDirPath+"/"+configName);
	Boolean status;
	if (configName.endsWith(".disabled"))
	    status = config.renameTo(new File(configName.replace(".disabled", "")));
	else
	    status = config.renameTo(new File(configName+".disabled"));
	result.put("returnVal", status);
	return result;
    }

    private JSONObject getList(String listType, ServiceMessage msg)
	throws JSONException, LSException {
	ReturnResult ret = executeCMD(ipkgBaseCommand + listType);
	if (ret.returnValue==0) {
	    JSONObject list = new JSONObject();
	    for (int i=0; i<ret.stdOut.size()-1;i++) {
		String[] item = ret.stdOut.get(i).split(" - ", 2);
		JSONObject info = new JSONObject();
		String name = item[0].trim();
		String version = item[1].trim();
		String description = null;
		if (item.length==3)
		    description = item[2].trim();
		info.put("version", version);
		info.put("description", description);
		if (!list.has(name))
		    list.put(name, info);
		else {
		    JSONObject dupeInfo = list.getJSONObject(name);
		    int comparison = compareVersions(version.split("\\."), dupeInfo.get("version").toString().split("\\."));
		    if (comparison==1)
			list.put(name, info);
		}
	    }
	    return list;
	}
	return null;
    }

    private JSONObject getInfo(String packageName, ServiceMessage msg)
	throws JSONException, LSException {
	ReturnResult ret;
	if (packageName==null)
	    ret = executeCMD(ipkgBaseCommand + "info");
	else
	    ret = executeCMD(ipkgBaseCommand + "info " + packageName);
	if (ret.returnValue==0) {
	    JSONArray infoList = new JSONArray();
	    JSONObject info = new JSONObject();
	    for (String line : ret.stdOut) {
		if (line.trim().compareTo("Successfully terminated.")!=0) {
		    if (line.trim().length()==0) {
			infoList.put(info);
			info = new JSONObject();
		    } else {
			String[] item = line.split(": ", 2);
			String key = item[0].trim();
			String value = item[1].trim();
			info.put(key,value);
		    }
		}
	    }
	    JSONObject reply = new JSONObject();
	    reply.put("info", infoList);
	    return reply;
	}
	return null;
    }

    private JSONObject getCategories(ServiceMessage msg)
	throws JSONException, LSException {
	LinkedHashSet<String> categories = new LinkedHashSet<String>();
	JSONObject list = getInfo(null, msg);
	if (list==null)
	    return null;
	JSONArray infos = list.getJSONArray("info");
	if (infos!=null && infos.length()>0) {
	    for (int i=0; i<infos.length(); i++) {
		String category = infos.getJSONObject(i).get("Section").toString().trim();
		if (category.length()>0) {
		    categories.add(category);
		}
	    }
	}
	if (!categories.isEmpty()) {
	    JSONArray catlist = new JSONArray();
	    for (String cat : categories)
		catlist.put(cat);
	    JSONObject reply = new JSONObject();
	    reply.put("categories", catlist);
	    return reply;
	} else
	    return null;
    }

    @SuppressWarnings("unchecked")
	private JSONObject getUpgrades(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject upgrades = new JSONObject();
	JSONObject allList = getList("list", msg);
	JSONObject installedList = getList("list_installed", msg);
	Iterator<String> installedListIter = installedList.keys();
	while (installedListIter.hasNext()) {
	    String packageKey = installedListIter.next();
	    JSONObject item = installedList.getJSONObject(packageKey);
	    JSONObject potentialUpgrade = allList.getJSONObject(packageKey);
	    String[] installedVersionString = item.get("version").toString().split("\\.");
	    String[] potentialUpgradeVersionString = potentialUpgrade.get("version").toString().split("\\.");
	    int comparison = compareVersions(installedVersionString, potentialUpgradeVersionString);
	    if (comparison==-1)
		upgrades.put(packageKey,potentialUpgrade.get("version").toString());
	}
	if (upgrades.length()>0)
	    return upgrades;
	else
	    return null;
    }

    private JSONObject doUpdate(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD(ipkgBaseCommand + "update");
	reply.put("returnVal",ret.returnValue);
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
	    reply.put("stage","confirm");
	    reply.put("errorText", "Confirmation requested for 'prerm' script execution");
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
	reply.put("returnVal",ret.returnValue);
	reply.put("outputText", ret.stdOut.toString());
	reply.put("errorText", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'rescan' operation");
	}
	return reply;
    }

    private JSONObject doRestartLunaSysMgr(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("stop LunaSysMgr ; start LunaSysMgr");
	reply.put("returnVal",ret.returnValue);
	reply.put("outputText", ret.stdOut.toString());
	reply.put("errorText", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartlunasysmgr' operation");
	}
	return reply;
    }

    private JSONObject doRestartJavaServiceBoot(ServiceMessage msg)
	throws JSONException, LSException {
	JSONObject reply = new JSONObject();
	ReturnResult ret = executeCMD("stop java-serviceboot ; start java-serviceboot");
	reply.put("returnVal",ret.returnValue);
	reply.put("outputText", ret.stdOut.toString());
	reply.put("errorText", ret.stdErr.toString());
	if (ret.returnValue!=0) {
	    reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
	    reply.put("errorText", "Failure during 'restartjavaserviceboot' operation");
	}
	return reply;
    }

    /* ============================ DBUS Methods =============================*/

    @LunaServiceThread.PublicMethod
	public void list(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getList("list", msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'list' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void list_installed(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getList("list_installed", msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'installed list' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void list_upgrades(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getUpgrades(msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'upgrade list' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void info(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    String pkg = null;
	    if (msg.getJSONPayload().has("package"))
		pkg = msg.getJSONPayload().getString("package").trim();
	    JSONObject reply = getInfo(pkg, msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'info' operation");
	} else
	    ipkgDirNotReady(msg);
    }

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
	public void list_categories(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getCategories(msg);
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'list categories' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void rescan(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doRescan(msg);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void restartlunasysmgr(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doRestartLunaSysMgr(msg);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void restartjavaserviceboot(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = doRestartJavaServiceBoot(msg);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void list_configs(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = getConfigs();
	    if (reply!=null)
		msg.respond(reply.toString());
	    else
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION,
				 "Failure during 'get configs' operation");
	} else
	    ipkgDirNotReady(msg);
    }

    @LunaServiceThread.PublicMethod
	public void toggle_config(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    if (msg.getJSONPayload().has("config")) {
		msg.respond(toggleConfigState(msg.getJSONPayload().getString("config").trim()).toString());
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
					reply.put("stage","unlock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,rw /");
					reply.put("returnVal",ret.returnValue);
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
				    if (ret.returnValue!=0) {
					reply.put("stage","failed");
					reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					reply.put("errorText", "Failure during 'postinst' operation");
					origmsg.respond(reply.toString());
					return;
				    }
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("stage","lock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,ro /");
					reply.put("returnVal",ret.returnValue);
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
					reply.put("stage","unlock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,rw /");
					reply.put("returnVal",ret.returnValue);
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
				    if (ret.returnValue!=0) {
					reply.put("stage","failed");
					reply.put("errorCode", ErrorMessage.ERROR_CODE_METHOD_EXCEPTION);
					reply.put("errorText", "Failure during 'prerm' operation");
					origmsg.respond(reply.toString());
					return;
				    }
				    if (isEmulator == false) {
					reply.put("returnVal",0);
					reply.put("stage","lock");
					origmsg.respond(reply.toString());
					ret = executeCMD("/bin/mount -o remount,ro /");
					reply.put("returnVal",ret.returnValue);
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
	public void status(ServiceMessage msg)
	throws JSONException, LSException {
	if (ipkgReady) {
	    JSONObject reply = new JSONObject();
	    reply.put("returnVal",true);
	    msg.respond(reply.toString());
	} else
	    ipkgDirNotReady(msg);
    }

}
