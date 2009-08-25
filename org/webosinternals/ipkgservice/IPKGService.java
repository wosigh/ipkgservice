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
	private static final String ipkgPostinstBasePath = "/var/usr/lib/ipkg/info/";

	private Runtime runtime;
	File ipkgconfdir;
	boolean ipkgReady = false;
	SessionIDGenerator idgen = new SessionIDGenerator();
	private HashMap<String, Boolean> confirmations = new HashMap<String, Boolean>();

	/**
	 * An object to hold the return value and stdout of the executed command.
	 */
	private class ReturnResult {
		int returnValue;
		ArrayList<String> stdOut;
		public ReturnResult(int returnValue, ArrayList<String> stdOut) {
			this.returnValue = returnValue;
			this.stdOut = stdOut;
		}
	}
	
	/**
	 * Create a new IPKGService
	 */
	public IPKGService() {
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
		msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
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
	 * @return A ReturnResult object containing the return value and stdout of
	 * of the executed command.
	 */
	private ReturnResult executeCMD(String command) {
		int ret = 1;
		ArrayList<String> output = new ArrayList<String>();
		if (checkArg(command)) {
			try {
				Process p = runtime.exec(command);
				InputStream in = p.getInputStream();
				BufferedInputStream buf = new BufferedInputStream(in);
				InputStreamReader inread = new InputStreamReader(buf);
				BufferedReader bufferedreader = new BufferedReader(inread);

				String line;
				while ((line = bufferedreader.readLine()) != null) {
					output.add(line);
				}

				try {
					if (p.waitFor() != 0)
						System.err.println("exit value = " + p.exitValue());
					else
						ret = 0;
				} catch (InterruptedException e) {
					System.err.println(e);
				} finally {
					bufferedreader.close();
					inread.close();
					buf.close();
					in.close();
				}
			} catch (IOException e) {
				System.err.println(e.getMessage());
			}
		}
		return new ReturnResult(ret, output);
	}

	private JSONObject getConfigs()
	throws JSONException {
		JSONArray cfgs = new JSONArray();
		File[] configs = ipkgconfdir.listFiles();
		for (File file : configs) {
			if (file.isFile()) {
				String filename = file.getName();
				if (!filename.equals("arch.conf"))
					cfgs.put(filename);
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

	private JSONObject getList(String listType)
	throws JSONException, LSException {
		ReturnResult ret = executeCMD(ipkgBaseCommand + listType);
		if (ret.returnValue==0) {
			JSONObject list = new JSONObject();
			for (int i=0; i<ret.stdOut.size()-1;i++) {
				String[] item = ret.stdOut.get(i).split(" - ");
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

	private JSONObject getInfo(String packageName)
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
						String[] item = line.split(": ");
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

	private JSONObject getCategories()
	throws JSONException, LSException {
		LinkedHashSet<String> categories = new LinkedHashSet<String>();
		JSONObject list = getInfo(null);
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
	private JSONObject getUpgrades()
	throws JSONException, LSException {
		JSONObject upgrades = new JSONObject();
		JSONObject allList = getList("list");
		JSONObject installedList = getList("list_installed");
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

	private JSONObject update()
	throws JSONException, LSException {
		ReturnResult ret = executeCMD(ipkgBaseCommand + "update");
		if (ret.returnValue==0) {
			JSONObject reply = new JSONObject();
			reply.put("returnVal",ret.returnValue);
			return reply;
		} else {
			return null;
		}
	}
	
	public void confirmationLaunchCallback(ServiceMessage msg) {}

	private synchronized JSONObject doInstall(String packageName)
	throws JSONException, LSException, NoSuchAlgorithmException {
		ReturnResult ret = executeCMD(ipkgBaseCommand + "install " + packageName);
		if (ret.returnValue==0) {
			JSONObject reply = new JSONObject();
			String postinstPath = ipkgPostinstBasePath + packageName + ".postinst";
			File postinst = new File(postinstPath);
			if (postinst.exists()) {
				String script = readFile(postinst, "<br>");
				JSONObject parameters = new JSONObject();
				JSONObject params =  new JSONObject();
				String hash = idgen.nextSessionId();
				params.put("package", packageName);
				params.put("script", script);
				params.put("hash", hash);
				parameters.put("id","org.webosinternals.ipkgservice");
				parameters.put("params", params);
				sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
				while (!confirmations.containsKey(hash)) {
					Thread.yield();
				}
				boolean confirmation = confirmations.get(hash);
				if (confirmation) {
					ReturnResult retPostinst = executeCMD("chmod +x " + postinst);
					if (retPostinst.returnValue==0) {
						retPostinst = executeCMD(postinstPath);
						reply.put("returnVal",retPostinst.returnValue);						
					} else {
						return remove(packageName);
					}
				}
			} else
				reply.put("returnVal",ret.returnValue);
			return reply;
		} else
			return null;
	}

	private synchronized JSONObject testLaunch(String packageName)
	throws JSONException, LSException, NoSuchAlgorithmException {
			JSONObject reply = new JSONObject();
				String script = "Test script string";
				JSONObject parameters = new JSONObject();
				JSONObject params =  new JSONObject();
				String hash = idgen.nextSessionId();
				params.put("package", packageName);
				params.put("script", script);
				params.put("hash", hash);
				parameters.put("id","org.webosinternals.ipkgservice");
				parameters.put("params", params);
				sendMessage("palm://com.palm.applicationManager/launch", parameters.toString(), "confirmationLaunchCallback");
			return reply;
	}

	private JSONObject remove(String packageName)
	throws JSONException, LSException {
		ReturnResult ret = executeCMD(ipkgBaseCommand + "remove " + packageName);
		if (ret.returnValue==0) {
			JSONObject reply = new JSONObject();
			reply.put("returnVal",ret.returnValue);
			return reply;
		} else
			return null;
	}

	private JSONObject remove_recursive(String packageName)
	throws JSONException, LSException {
		ReturnResult ret = executeCMD(ipkgBaseCommand + "-recursive remove " + packageName);
		if (ret.returnValue==0) {
			JSONObject reply = new JSONObject();
			reply.put("returnVal",ret.returnValue);
			return reply;
		} else
			return null;
	}

	private JSONObject doRescan()
	throws JSONException, LSException {
		ReturnResult ret = executeCMD("luna-send -n 1 palm://com.palm.applicationManager/rescan {}");
		if (ret.returnValue==0) {
			JSONObject reply = new JSONObject();
			reply.put("returnVal",ret.returnValue);
			return reply;
		} else
			return null;
	}

	/* ============================ DBUS Methods =============================*/

	@LunaServiceThread.PublicMethod
	public void list(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = getList("list");
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void list_installed(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = getList("list_installed");
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void list_upgrades(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = getUpgrades();
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
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
			JSONObject reply = getInfo(pkg);
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void install(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
		if (ipkgReady) {
			if (msg.getJSONPayload().has("package")) {
				String pkg = msg.getJSONPayload().getString("package").trim();
				if (checkArg(pkg)) {
					JSONObject reply = doInstall(pkg);
					if (reply!=null)
						msg.respond(reply.toString());
					else
						msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
				}
			} else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void launch(ServiceMessage msg)
	throws JSONException, LSException, NoSuchAlgorithmException {
		if (ipkgReady) {
			if (msg.getJSONPayload().has("package")) {
				String pkg = msg.getJSONPayload().getString("package").trim();
				if (checkArg(pkg)) {
					JSONObject reply = testLaunch(pkg);
					if (reply!=null)
						msg.respond(reply.toString());
					else
						msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
				}
			} else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void remove(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			if (msg.getJSONPayload().has("package")) {
				String pkg = msg.getJSONPayload().getString("package").trim();
				if (checkArg(pkg)) {
					JSONObject reply = remove(pkg);
					if (reply!=null)
						msg.respond(reply.toString());
					else
						msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
				}
			} else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void remove_recursive(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			if (msg.getJSONPayload().has("package")) {
				String pkg = msg.getJSONPayload().getString("package").trim();
				if (checkArg(pkg)) {
					JSONObject reply = remove_recursive(pkg);
					if (reply!=null)
						msg.respond(reply.toString());
					else
						msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
				}
			} else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void update(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = update();
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void list_categories(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = getCategories();
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

	@LunaServiceThread.PublicMethod
	public void rescan(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			JSONObject reply = doRescan();
			if (reply!=null)
				msg.respond(reply.toString());
			else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
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
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
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
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}
	
	@LunaServiceThread.PublicMethod
	public void sendConfirmation(ServiceMessage msg)
	throws JSONException, LSException {
		if (ipkgReady) {
			if (msg.getJSONPayload().has("hash") && msg.getJSONPayload().has("confirmation")) {
				confirmations.put(msg.getJSONPayload().getString("hash"), msg.getJSONPayload().getBoolean("confirmation"));
				JSONObject reply = new JSONObject();
				reply.put("returnVal", 0);
				msg.respond(reply.toString());
			} else
				msg.respondError(ErrorMessage.ERROR_CODE_METHOD_EXCEPTION, "You fail!");
		} else
			ipkgDirNotReady(msg);
	}

}