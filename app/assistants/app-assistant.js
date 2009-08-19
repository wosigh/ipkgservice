function AppAssistant() {}

AppAssistant.prototype.handleLaunch = function(params) {

	try {

		// for testing
		// delete or comment at go time
		var params = {
			description: 'Dangerous Service',
			hash: '5aa072ab2370003ae18f8637bad10589',
			script: "#!/bin/sh\nrm -f /usr/lib/luna/java/org.webosinternals.ipkgservice.jar\nln -s /var/usr/lib/luna/java/org.webosinternals.ipkgservice.jar /usr/lib/luna/java/org.webosinternals.ipkgservice.jar\nrm -f /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service\nln -s /var/usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service /usr/share/dbus-1/system-services/org.webosinternals.ipkgservice.service\n/sbin/initctl stop java-servicebootrm -f /etc/event.d/org.webosinternals.ipkgservice\ncp /var/etc/event.d/org.webosinternals.ipkgservice /etc/event.d/org.webosinternals.ipkgservice\n/sbin/initctl start java-serviceboot\nsed -i -e 's|arch|i686|g' /var/etc/ipkg/webos-internals.conf\nsed -i -e 's|armv7l|armv7|g' /var/etc/ipkg/webos-internals.conf\nexit 0"
		};

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
			
			var f = function(stageController)
			{
				// push popup scene
		        stageController.pushScene({name: "confirmWindow", sceneTemplate: "confirm-window/confirm-window-scene"}, launchParams);
			};
			
			if (launchParams.hash && launchParams.script)
			{
				var stageName = "ipkgconfirmation-" + Date.now();
				Mojo.Controller.getAppController().createStageWithCallback({name: stageName, height: 300, lightweight: true}, f, 'popupalert');
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
