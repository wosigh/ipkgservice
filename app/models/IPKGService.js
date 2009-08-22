IPKGService.identifier = 'palm://org.webosinternals.ipkgservice';

function IPKGService() {

}

IPKGService.update = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'update',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.list_categories = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'list_categories',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.list = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'list',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.list_installed = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'list_installed',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.list_upgrades = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'list_upgrades',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.rescan = function(callback) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'rescan',
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.info = function(callback, pkg) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'info',
		parameters: {"package":pkg},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.install = function(callback, pkg) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'install',
		parameters: {"package":pkg},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.remove = function(callback, pkg) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'remove',
		parameters: {"package":pkg},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.sendConfirmation = function(callback, hash, confirmation) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'sendConfirmation',
		parameters: {"hash":hash,"confirmation":confirmation},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

