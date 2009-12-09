IPKGService.identifier = 'palm://org.webosinternals.ipkgservice';

function IPKGService() {}

IPKGService.confirmInstall = function(callback, hash, confirmation) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'confirmInstall',
		parameters: {"hash":hash,"confirmation":confirmation},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.confirmRemove = function(callback, hash, confirmation, replace) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'confirmRemove',
		parameters: {"hash":hash,"confirmation":confirmation,"replace":replace},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.confirmAdd = function(callback, hash, confirmation) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'confirmAdd',
		parameters: {"hash":hash,"confirmation":confirmation},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

IPKGService.confirmDelete = function(callback, hash, confirmation) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'confirmDelete',
		parameters: {"hash":hash,"confirmation":confirmation},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

