function AppAssistant() {}

AppAssistant.prototype.handleLaunch = function(params) {

	try {

		/*// for testing script confirmation
        var params = {
	        "package": 'org.webosinternals.demo',
	        title: 'Secure Consent Demo',
	        type: 'install',
			hash: '5aa072ab2370003ae18f8637bad10589',
			script: "#!/bin/sh<br />rm -f /usr/lib/luna/java/org.webosinternals.ipkgservice.jar<br />ln -s /var/usr/lib/luna/java/org.webosinternals.ipkgservice.jar /usr/lib/luna/java/org.webosinternals.ipkgservice.jar<br />rm -f /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service<br />ln -s /var/usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service<br />/sbin/initctl stop java-servicebootrm -f /etc/event.d/org.webosinternals.ipkgservice<br />cp /var/etc/event.d/org.webosinternals.ipkgservice /etc/event.d/org.webosinternals.ipkgservice<br />/sbin/initctl start java-serviceboot<br />sed -i -e 's|arch|i686|g' /var/etc/ipkg/webos-internals.conf<br />sed -i -e 's|armv7l|armv7|g' /var/etc/ipkg/webos-internals.conf<br />exit 0"
			+ "<br /><br />#!/bin/sh<br />rm -f /usr/lib/luna/java/org.webosinternals.ipkgservice.jar<br />ln -s /var/usr/lib/luna/java/org.webosinternals.ipkgservice.jar /usr/lib/luna/java/org.webosinternals.ipkgservice.jar<br />rm -f /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service<br />ln -s /var/usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service<br />/sbin/initctl stop java-servicebootrm -f /etc/event.d/org.webosinternals.ipkgservice<br />cp /var/etc/event.d/org.webosinternals.ipkgservice /etc/event.d/org.webosinternals.ipkgservice<br />/sbin/initctl start java-serviceboot<br />sed -i -e 's|arch|i686|g' /var/etc/ipkg/webos-internals.conf<br />sed -i -e 's|armv7l|armv7|g' /var/etc/ipkg/webos-internals.conf<br />exit 0"
		};*/
		/*// for testing config confirmation
        var params = {
	        config: 'Example Feed',
	        url: 'http://example.com/feed/all',
	        type: 'install',
			hash: '5aa072ab2370003ae18f8637bad10589'
		};*/
	    

		var launchParams = {};

		if (Object.isString(params)) 
		{
			if (params.isJSON())
			{
				launchParams = params.evalJSON();
			}
		}
		else 
		{
			launchParams = params;
		}
		
		// really, this should never be false unless the appinfo is broken
		// we could probably do without it.
		if (Mojo.Controller.appInfo.noWindow)
		{
			
			var scriptFunction = function(stageController)
			{
		        stageController.pushScene({name: "confirmWindow", sceneTemplate: "confirm-window/confirm-window-scene"}, launchParams);
			};
			var configFunction = function(stageController)
			{
		        stageController.pushScene({name: "configWindow", sceneTemplate: "config-window/config-window-scene"}, launchParams);
			};
			var manualFunction = function(stageController)
			{
		        stageController.pushScene({name: "manualOpen", sceneTemplate: "manual-open/manual-open-scene"}, launchParams);
			};
			
			if (launchParams.hash && launchParams.script) 
			{
				var stageName = "ipkgconfirmation-" + Date.now();
				Mojo.Controller.getAppController().createStageWithCallback(
				{
					name: stageName,
					height: 300,
					lightweight: true
				}, scriptFunction, 'popupalert');
			}
			else if (launchParams.hash && launchParams.config) 
			{
				var stageName = "ipkgconfig-" + Date.now();
				Mojo.Controller.getAppController().createStageWithCallback(
				{
					name: stageName,
					height: 200,
					lightweight: true
				}, configFunction, 'popupalert');
			}
			else 
			{
				var stageName = "ipkgmanuallaunch-" + Date.now();
				Mojo.Controller.getAppController().createStageWithCallback(
				{
					name: stageName,
					height: 300,
					lightweight: true
				}, manualFunction, 'popupalert');
			}
			
		}
		else if (params.banner)
		{
			Mojo.Log.warn("Notifications not yet implemented.");
		}

	}
	catch (e)
	{
		Mojo.Log.logException(e, "AppAssistant#handleLaunch");
	}

}

AppAssistant.prototype.cleanup = function() {}
