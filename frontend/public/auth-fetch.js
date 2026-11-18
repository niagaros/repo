// Sends the signed-in user's Cognito access token with every request to the Niagaros API, so the backend can
// enforce tenant isolation (each caller only reaches accounts they own). Loaded before any page script.
// Token source: the React shell (frontend/src/App.tsx) stores the Cognito access token from fetchAuthSession()
// in localStorage['niagaros_token'] after login, before redirecting to the dashboard pages.
// Which calls get it: only https fetch() requests whose host is exactly API_HOST (the API Gateway); requests to other hosts
// and same-origin files (config.json, scripts) are left untouched. An Authorization header set by the caller wins.
// A 401 from the API means the session is missing or expired -> back to the login page.
(function () {
  var API_HOST = 'hzf92ft6j7.execute-api.eu-west-1.amazonaws.com';
  var nativeFetch = window.fetch.bind(window);

  // Exact host match on the parsed URL: a substring check would also hand the token to
  // e.g. https://evil.example/?x=execute-api.eu-west-1.amazonaws.com.
  function isApiUrl(url) {
    try {
      var u = new URL(url, location.href);
      return u.protocol === 'https:' && u.hostname === API_HOST;
    } catch (e) {
      return false;
    }
  }

  window.fetch = function (input, init) {
    var url = (typeof input === 'string' || input instanceof URL) ? String(input) : (input && input.url) || '';
    var isApi = isApiUrl(url);
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
