function ConfigWindowAssistant(params)
{
	// we will need these later
	this.params = params;
	
	// this is so deactivate will know if we've sent a command or not
	this.sentCommand = false;
}

ConfigWindowAssistant.prototype.setup = function()
{
	// fill in wordage for type of confirmation
	if (this.params.type === "add") this.controller.get('type').innerHTML = 'add';
	else if (this.params.type === "delete") this.controller.get('type').innerHTML = 'delete';
	
	// fill in name
	if (!this.params.config) this.params.config = 'Unnamed';
	this.controller.get('name').innerHTML = this.params.config;
	
	// fill in url
	if (!this.params.url) this.params.url = 'Unknown';
	this.controller.get('url').innerHTML = this.params.url.replace(/http:\/\//, '');
	
	// setup buttons
	this.controller.setupWidget('ok-button', {}, {buttonLabel: $L('Yes'), buttonClass: 'affirmative'});
    Mojo.Event.listen(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
	this.controller.setupWidget('cancel-button', {}, {buttonLabel: $L('No'), buttonClass: 'negative'});
    Mojo.Event.listen(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}

ConfigWindowAssistant.prototype.okButton = function()
{
	// send ok command here
	//console.log('Popup [Ok Button]');
	
	if (this.params.type === "add") {
	    IPKGService.confirmAdd(this.confirmCallback.bindAsEventListener(this), this.params.hash, true);
	}
	if (this.params.type === "delete") {
	    IPKGService.confirmDelete(this.confirmCallback.bindAsEventListener(this), this.params.hash, true);
	}
	
	// if the ok is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ConfigWindowAssistant.prototype.cancelButton = function()
{
	// send cancel command here
	//console.log('Popup [Cancel Button]');
	
	if (this.params.type === "add") {
	    IPKGService.confirmAdd(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
	}
	if (this.params.type === "delete") {
	    IPKGService.confirmDelete(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
	}
	
	// if the cancel is successful
	this.sentCommand = true;
	
	// close the popup
	this.controller.window.close();
}

ConfigWindowAssistant.prototype.confirmCallback = function(payload)
{
	// for lack of anything better to do with the results right now
	//console.log(payload);
}

ConfigWindowAssistant.prototype.activate = function(event) {}

ConfigWindowAssistant.prototype.deactivate = function(event)
{
	// if we haven't sent a command, we should send a cancel.
	// this would happen if they hit the home button or used the back gesture.
	if (!this.sentCommand)
	{
		// send cancel command here
		//console.log('Popup [Cancel Gesture]');
		
		if (this.params.type === "add") {
		    IPKGService.confirmAdd(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
		}
		if (this.params.type === "delete") {
		    IPKGService.confirmDelete(this.confirmCallback.bindAsEventListener(this), this.params.hash, false);
		}
	}
}

ConfigWindowAssistant.prototype.cleanup = function(event)
{
	// cleanup our event listeners
    Mojo.Event.stopListening(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
    Mojo.Event.stopListening(this.controller.get('cancel-button'), Mojo.Event.tap, this.cancelButton.bind(this));
}
