function ConfirmWindowAssistant(params)
{
	// we will need these later
	this.params = params;
	
	// this is so deactivate will know if we've sent a command or not
	this.sentCommand = false;
}

ConfirmWindowAssistant.prototype.setup = function()
{
	// fill in description
	if (!this.params.title) this.params.title = 'Unnamed';
	this.controller.get('description').innerHTML = this.params.title;
	
	// fill in wordage for type of confirmation
	if (this.params.type === "install") this.controller.get('type').innerHTML = ' after installation';
	else if (this.params.type === "remove") this.controller.get('type').innerHTML = ' before removal';
	else if (this.params.type === "replace") this.controller.get('type').innerHTML = ' before replacement';
	
	// setup buttons
	this.controller.setupWidget('ok-button', {}, {buttonLabel: $L("Ok"), buttonClass: 'affirmative'});
    Mojo.Event.listen(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
	this.controller.setupWidget('view-button', {}, {buttonLabel: $L("View")});
    Mojo.Event.listen(this.controller.get('view-button'), Mojo.Event.tap, this.viewButton.bind(this));
	this.controller.setupWidget('cancel-button', {}, {buttonLabel: $L("Cancel"), buttonClass: 'negative'});
    Mojo.Event.listen(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}

ConfirmWindowAssistant.prototype.okButton = function()
{
	// send ok command here
	//console.log('Popup [Ok Button]');

	if (this.params.type === "install") {
	    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, true);
	}
	if (this.params.type === "remove") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, true, false);
	}
	if (this.params.type === "replace") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, true, true);
	}
	
	// if the ok is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ConfirmWindowAssistant.prototype.viewButton = function()
{
	// set this even though we're not sending a command,
	// but we expect the script view scene to do something
	this.sentCommand = true;
	
	// launch script view scene
	var stageName = "ipkgscriptview-" + Date.now();
	this.controller.stageController.getAppController().createStageWithCallback({name: stageName, lightweight: true}, this.pushView.bind(this));
	
	// close the popup
	this.controller.window.close();
}

ConfirmWindowAssistant.prototype.pushView = function(stageController)
{
	// push view scene
    stageController.pushScene({name: "scriptView", sceneTemplate: "script-view/script-view-scene"}, this.params);
};

ConfirmWindowAssistant.prototype.cancelButton = function()
{
	// send cancel command here
	//console.log('Popup [Cancel Button]');

	if (this.params.type === "install") {
	    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
	}
	if (this.params.type === "remove") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false, false);
	}
	if (this.params.type === "replace") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false, true);
	}
	
	// if the cancel is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ConfirmWindowAssistant.prototype.confirmCallback = function(payload)
{
	// for lack of anything better to do with the results right now
	//console.log(payload);
}

ConfirmWindowAssistant.prototype.activate = function(event) {}

ConfirmWindowAssistant.prototype.deactivate = function(event)
{
	// if we haven't sent a command, we should send a cancel.
	// this would happen if they hit the home button or used the back gesture.
	if (!this.sentCommand)
	{
		// send cancel command here
		//console.log('Popup [Cancel Gesture]');

		if (this.params.type === "install") {
		    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
		}
		if (this.params.type === "remove") {
		    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false, false);
		}
		if (this.params.type === "replace") {
		    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false, true);
		}
	}
}

ConfirmWindowAssistant.prototype.cleanup = function(event)
{
	// cleanup our event listeners
    Mojo.Event.stopListening(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
    Mojo.Event.stopListening(this.controller.get('view-button'), Mojo.Event.tap, this.viewButton.bind(this));
    Mojo.Event.stopListening(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}
