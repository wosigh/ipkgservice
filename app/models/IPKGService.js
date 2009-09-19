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

IPKGService.confirmRemove = function(callback, hash, confirmation) {
	var request = new Mojo.Service.Request(IPKGService.identifier, {
		method: 'confirmRemove',
		parameters: {"hash":hash,"confirmation":confirmation},
		onSuccess: callback,
		onFailure: callback
	});
	return request;
}

