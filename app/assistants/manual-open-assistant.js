function ManualOpenAssistant(){}

ManualOpenAssistant.prototype.setup = function()
{
	// setup buttons
	this.controller.setupWidget('ok-button', {}, {buttonLabel: $L('Ok. I\'ll ignore this icon.'), buttonClass: 'affirmative'});
    Mojo.Event.listen(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
}

ManualOpenAssistant.prototype.okButton = function()
{
	// send ok command here
	console.log('Popup [Ok Button]');
	
	// close the popup
	this.controller.window.close();
}

ManualOpenAssistant.prototype.activate = function(event) {}

ManualOpenAssistant.prototype.deactivate = function(event) {}

ManualOpenAssistant.prototype.cleanup = function(event)
{
	// cleanup our event listeners
    Mojo.Event.stopListening(this.controller.get('ok-button'), Mojo.Event.tap, this.okButton.bind(this));
}
