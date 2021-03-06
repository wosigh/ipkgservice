function ScriptViewAssistant(params)
{
	// we will need these later
	this.params = params;
	
	// this is so deactivate will know if we've sent a command or not
	this.sentCommand = false;
}

ScriptViewAssistant.prototype.setup = function()
{
	// dark theme
	this.controller.document.body.className = 'palm-dark';
	
	// fill in description
	if (!this.params.title) this.params.title = 'Unnamed';
	this.controller.get('description').innerHTML = this.params.title;
	
	// fill in script
	this.controller.get('script').innerHTML = this.params.script;
	
	// setup scroller
	this.controller.setupWidget('scriptScroller', {mode: 'dominant'});
	
	// setup buttons
	this.controller.setupWidget('ok-button', {}, {buttonLabel: $L("Ok"), buttonClass: 'affirmative'});
	Mojo.Event.listen(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
	this.controller.setupWidget('cancel-button', {}, {buttonLabel: $L("Cancel"), buttonClass: 'negative'});
	Mojo.Event.listen(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}

ScriptViewAssistant.prototype.okButton = function()
{
	// send ok command here
	//console.log('Script View [Ok Button]');

	if (this.params.type === "install") {
	    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, true);
	}
	if (this.params.type === "remove") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, true);
	}
	
	// if the ok is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ScriptViewAssistant.prototype.cancelButton = function()
{
	// send cancel command here
	//console.log('Script View [Cancel Button]');

	if (this.params.type === "install") {
	    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
	}
	if (this.params.type === "remove") {
	    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
	}
	
	// if the cancel is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ScriptViewAssistant.prototype.confirmCallback = function(payload)
{
	// for lack of anything better to do with the results right now
	//console.log(payload);
}

ScriptViewAssistant.prototype.activate = function(event) {}

ScriptViewAssistant.prototype.deactivate = function(event)
{
	// if we haven't sent a command, we should send a cancel.
	// this would happen if they hit the switched to card view and dismissed it.
	if (!this.sentCommand)
	{
		// send cancel command here
		//console.log('Script View [Card Discard]');

		if (this.params.type === "install") {
		    IPKGService.confirmInstall(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
		}
		if (this.params.type === "remove") {
		    IPKGService.confirmRemove(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
		}
	}
}

ScriptViewAssistant.prototype.cleanup = function(event)
{
	// cleanup our event listeners
    Mojo.Event.stopListening(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
    Mojo.Event.stopListening(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}
