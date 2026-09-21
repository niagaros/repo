// Sends the signed-in user's Cognito access token with every request to the Niagaros API, so the backend can
// enforce tenant isolation (each caller only reaches accounts they own). Loaded before any page script.
// A 401 from the API means the session is missing or expired -> back to the login page.
(function () {
  var API_HOST = 'execute-api.eu-west-1.amazonaws.com';
  var nativeFetch = window.fetch.bind(window);

  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    var isApi = url.indexOf(API_HOST) !== -1;
    if (isApi) {
      var token = null;
      try { token = localStorage.getItem('niagaros_token'); } catch (e) { /* storage blocked */ }
      if (token) {
        init = Object.assign({}, init);
        var headers = new Headers(init.headers || (typeof input !== 'string' && input.headers) || {});
        if (!headers.has('Authorization')) headers.set('Authorization', 'Bearer ' + token);
        init.headers = headers;
      }
    }
    return nativeFetch(input, init).then(function (res) {
      if (isApi && res.status === 401) {
        try { localStorage.removeItem('niagaros_token'); } catch (e) { /* ignore */ }
        location.href = '/';
      }
      return res;
    });
  };
})();
