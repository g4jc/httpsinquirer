/*
 * HTTPSDetect.js handles background Detection and http observation
 */

httpsinquirer.Cookies = {};
httpsinquirer_INCLUDE('Cookies', httpsinquirer.Cookies);
var OS = Cc["@mozilla.org/observer-service;1"]
        .getService(Ci.nsIObserverService);
////Not a great solution, but this is for problematic domains.
//Google image search over ssl is one, so we won't cache results there.
var cacheExempt = ["www.google.com", "translate.google.com", "encrypted.google.com"];
function QueryInterface(aIID) {
    if (aIID.equals(Ci.nsIObserver) || aIID.equals(Ci.nsISupports))
        return this;
    throw Cr.NS_NOINTERFACE;
}

//Watches HTTP responses, filters and calls Detection if needed
function observe(request, aTopic, aData) {
    if (aTopic == "http-on-examine-response") {
        request.QueryInterface(Ci.nsIHttpChannel);
        if (!httpsinquirer.prefs.getBoolPref("enable"))
            return;
        if ((request.responseStatus == 200 || request.responseStatus == 301
                || request.responseStatus == 304) && request.URI.scheme == "http")
            var loadFlags = httpsinquirer.Detect.getStringArrayOfLoadFlags(request.loadFlags);
        else
            return;
        if (loadFlags.indexOf("LOAD_DOCUMENT_URI") != -1 && loadFlags.indexOf("LOAD_INITIAL_DOCUMENT_URI") != -1) {
            if (httpsinquirer.Overlay.isWhitelisted(request.URI.host.toLowerCase())) {
                if (httpsinquirer.debug)
                    dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Host is whitelisted\n");
                return;
            }
            var browser = httpsinquirer.Detect.getBrowserFromChannel(request);
            if (browser == null) {
                if (httpsinquirer.debug)
                    dump("httpsinquirer browser cannot be found for channel\n");
                return;
            }

            var host = request.URI.host.toLowerCase();
            try {
                if (httpsinquirer.Detect.hostsMatch(browser.contentDocument.baseURIObject.host.toLowerCase(), host) &&
                        httpsinquirer.results.goodSSL.indexOf(request.URI.host.toLowerCase()) != -1) {
                    if (httpsinquirer.debug)
                        dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Good SSL already cached for host.\n");
                    httpsinquirer.Detect.handleCachedSSL(browser, request);
                    return;
                }
            } catch (e) {
                if (e.name == 'NS_ERROR_FAILURE')
                    dump("HTTPS Inquirer: cannot match URI to browser request.\n");
            }

//Push to whitelist so we don't spam with multiple Detection requests - may be removed later depending on result
            if (!httpsinquirer.Overlay.isWhitelisted(host) &&
                    !httpsinquirer.pbs.privateBrowsingEnabled) {
                httpsinquirer.results.whitelist.push(host);
                if (httpsinquirer.debug) {
                    dump("httpsinquirer Blocking Detection on " + request.URI.host + " until OK response received\n");
                    dump("httpsinquirer Starting HTTPS Detection for " + request.URI.asciiSpec + "\n");
                }
            }

            httpsinquirer.Detect.detectSSL(browser, request);
        }
    }
}

function register() {
    OS.addObserver(httpsinquirer.Detect, "http-on-examine-response", false);
}

function unregister() {
    try {
        OS.removeObserver(httpsinquirer.Detect, "http-on-examine-response");
    }
    catch (e) {/* already removed if enabled pref is false */
    }
}

function hostsMatch(host1, host2) {
//check domain name of page location and detected host. Slice after first . to ignore subdomains
    if (host1.slice(host1.indexOf(".", 0) + 1, host1.length) == host2.slice(host2.indexOf(".", 0) + 1, host2.length))
        return true;
    else
        return false;
}

//HTTPS Detection function - does HEAD falling back to GET, or just GET depending on user settings
function detectSSL(aBrowser, request) {
    var requestURL = request.URI.asciiSpec.replace("http://", "https://");
    //If user preference specifies GET Detection only
    if (!httpsinquirer.prefs.getBoolPref("headfirst")) {
        var getReq = new XMLHttpRequest();
        getReq.mozBackgroundRequest = true;
        getReq.open('GET', requestURL, true);
        getReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
        getReq.addEventListener("error",
                function(e) {
                    handleDetectionResponse(aBrowser, getReq)
                },false);
        getReq.onload = function(e) {
            handleDetectionResponse(aBrowser, getReq)
        };
        getReq.send(null);
    }
    else { //Otherwise, try HEAD and fall back to GET if necessary (default bahavior)
        var headReq = new XMLHttpRequest();
        headReq.mozBackgroundRequest = true;
        headReq.open('HEAD', requestURL, true);
        headReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
        headReq.onreadystatechange = function(aEvt) {
            if (headReq.readyState == 4) {
                if (headReq.status == 200 || headReq.status == 0 ||
                        (headReq.status != 405 && headReq.status != 403))
                    httpsinquirer.Detect.handleDetectionResponse(aBrowser, headReq);
                else if (headReq.status == 405 || headReq.status == 403) {
                    dump("httpsinquirer Detection falling back to GET for " + requestURL + "\n");
                    var getReq = new XMLHttpRequest();
                    getReq.mozBackgroundRequest = true;
                    getReq.open('GET', requestURL, true);
                    getReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
                    getReq.addEventListener("error",
                            function(e) {
                                handleDetectionResponse(aBrowser, getReq)
                            },false);
                    getReq.onload = function(e) {
                        handleDetectionResponse(aBrowser, getReq)
                    };
                    getReq.send(null);
                }
            }
        };
        headReq.send(null);
    }
}

//Get load flags for HTTP observer. We use these to filter normal http requests from page load requests
function getStringArrayOfLoadFlags(flags) {
    var flagsArr = [];
    //Look for the two load flags that indicate a page load (ignore others)
    if (flags & Ci.nsIChannel.LOAD_DOCUMENT_URI)
        flagsArr.push("LOAD_DOCUMENT_URI");
    if (flags & Ci.nsIChannel.LOAD_INITIAL_DOCUMENT_URI)
        flagsArr.push("LOAD_INITIAL_DOCUMENT_URI");
    return flagsArr;
}

//Used by HTTP observer to match requests to tabs
function getBrowserFromChannel(aChannel) {
    try {
        var notificationCallbacks = aChannel.notificationCallbacks ? aChannel.notificationCallbacks : aChannel.loadGroup.notificationCallbacks;
        if (!notificationCallbacks)
            return null;
        var domWin = notificationCallbacks.getInterface(Ci.nsIDOMWindow);
        return gBrowser.getBrowserForDocument(domWin.top.document);
    }
    catch (e) {
        return null;
    }
}

//If good SSL has alread been found during this session, skip new Detection and use this function
function handleCachedSSL(aBrowser, request) {
    if (request.responseStatus != 200 && request.responseStatus != 301 && request.responseStatus != 302)
        return;
    if (!httpsinquirer.Overlay.isWhitelisted(aBrowser.currentURI.host))
        httpsinquirer.Cookies.goodSSLFound(aBrowser.currentURI.host);
    var nb = gBrowser.getNotificationBox(aBrowser);
    var sslFoundButtons = [{
            label: httpsinquirer.strings.getString("httpsinquirer.main.whitelist"),
            accessKey: httpsinquirer.strings.getString("httpsinquirer.main.whitelistKey"),
            popup: null,
            callback: httpsinquirer.Overlay.whitelistDomain
        }, {
            label: httpsinquirer.strings.getString("httpsinquirer.main.noRedirect"),
            accessKey: httpsinquirer.strings.getString("httpsinquirer.main.noRedirectKey"),
            popup: null,
            callback: httpsinquirer.Overlay.redirectNotNow
        }, {
            label: httpsinquirer.strings.getString("httpsinquirer.main.yesRedirect"),
            accessKey: httpsinquirer.strings.getString("httpsinquirer.main.yesRedirectKey"),
            popup: null,
            callback: httpsinquirer.Overlay.redirect
        }];
    if (httpsinquirer.prefs.getBoolPref("autoforward"))
        httpsinquirer.Overlay.redirectAuto(aBrowser, request);
    else if (httpsinquirer.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsinquirer.prefs.getBoolPref("httpsfoundalert")) {

        nb.appendNotification(httpsinquirer.strings.getString("httpsinquirer.main.httpsFoundPrompt"),
                "httpsinquirer-https-found", 'chrome://httpsinquirer/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, sslFoundButtons);
        if (httpsinquirer.prefs.getBoolPref("dismissAlerts"))
            setTimeout(function() {
                httpsinquirer.removeNotification("httpsinquirer-https-found")
            }, httpsinquirer.prefs.getIntPref("alertDismissTime") * 1000, 'httpsinquirer-https-found');
    }
}

//Callback function for our HTTPS Detection request
function handleDetectionResponse(aBrowser, sslTest) {
//Session whitelist host and return if cert is bad or status is not OK.
    var host = sslTest.channel.URI.host.toLowerCase();
    var request = sslTest.channel;
    var cacheExempt = (httpsinquirer.Detect.cacheExempt.indexOf(host) != -1) ? true : false;
    if (cacheExempt) {
        if (httpsinquirer.debug)
            dump("httpsinquirer removing " + host + " from whitelist (exempt from saving results on this host)\n");
        httpsinquirer.Overlay.removeFromWhitelist(null, aBrowser.contentDocument.baseURIObject.host.toLowerCase());
    }

    var Codes = [200, 301, 302, 0];
    if (Codes.indexOf(sslTest.status) == -1 && httpsinquirer.results.goodSSL.indexOf(host) == -1) {
        if (httpsinquirer.debug)
            dump("httpsinquirer leaving " + host + " in whitelist (return status code " + sslTest.status + ")\n");
        return;
    }
    else if (sslTest.status == 0 && !httpsinquirer.Detect.testCertificate(request) && httpsinquirer.results.goodSSL.indexOf(host) == -1) {
        if (httpsinquirer.debug)
            dump("httpsinquirer leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else if (!httpsinquirer.Detect.testCertificate(request) && httpsinquirer.results.goodSSL.indexOf(host) == -1) {
        if (httpsinquirer.debug)
            dump("httpsinquirer leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else
        httpsinquirer.Overlay.removeFromWhitelist(null, host);
    //If the code gets to this point, the HTTPS is good.
    //Push host to good SSL list (remember result and skip repeat Detection)
    if (httpsinquirer.results.goodSSL.indexOf(host) == -1 && !httpsinquirer.pbs.privateBrowsingEnabled) {
        if (httpsinquirer.debug)
            dump("Pushing " + host + " to good SSL list\n");
        httpsinquirer.Overlay.removeFromWhitelist(null, host);
        if (!cacheExempt)
            httpsinquirer.Detect.addHostToGoodSSLList(host);
    }
    else if (!httpsinquirer.results.goodSSL.indexOf(aBrowser.contentDocument.baseURIObject.host.toLowerCase()) == -1
            && !httpsinquirer.pbs.privateBrowsingEnabled) {
        var altHost = aBrowser.contentDocument.baseURIObject.host.toLowerCase();
        if (httpsinquirer.debug)
            dump("Pushing " + altHost + " to good SSL list.\n");
        httpsinquirer.Overlay.removeFromWhitelist(null, altHost);
        if (!cacheExempt)
            httpsinquirer.Detect.addHostToGoodSSLList(altHost);
    }

//Check setting and automatically enforce HTTPS
    if (httpsinquirer.prefs.getBoolPref("autoforward"))
        httpsinquirer.Overlay.redirectAuto(aBrowser, request);
    //If auto-enforce is disabled, if host is not in tempNoAlerts (rule already saved)
    //and HTTPS Found alerts are enabled, alert user of good HTTPS
    else if (httpsinquirer.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsinquirer.prefs.getBoolPref("httpsfoundalert")) {
        if (httpsinquirer.Detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(), host)) {

            var nb = gBrowser.getNotificationBox(aBrowser);
            var sslFoundButtons = [{
                    label: httpsinquirer.strings.getString("httpsinquirer.main.whitelist"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.whitelistKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.whitelistDomain
                }, {
                    label: httpsinquirer.strings.getString("httpsinquirer.main.noRedirect"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.noRedirectKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.redirectNotNow
                }, {
                    label: httpsinquirer.strings.getString("httpsinquirer.main.yesRedirect"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.yesRedirectKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.redirect
                }];
            nb.appendNotification(httpsinquirer.strings.getString("httpsinquirer.main.httpsFoundPrompt"),
                    "httpsinquirer-https-found", 'chrome://httpsinquirer/skin/httpsAvailable.png',
                    nb.PRIORITY_INFO_HIGH, sslFoundButtons);
            httpsinquirer.Overlay.removeFromWhitelist(aBrowser.contentDocument, null);
            if (httpsinquirer.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function() {
                    httpsinquirer.removeNotification("httpsinquirer-https-found")
                }, httpsinquirer.prefs.getIntPref("alertDismissTime") * 1000, 'httpsinquirer-https-found');
        }
        else {
//Catches certain browser location changes and page content that had load flags to fire Detection
            if (httpsinquirer.debug)
                dump("Host mismatch, alert blocked (Document: " +
                        aBrowser.contentDocument.baseURIObject.host.toLowerCase() + " , Detection host: " + host + "\n");
        }
    }
}

function addHostToGoodSSLList(host) {
    httpsinquirer.results.goodSSL.push(host);
    httpsinquirer.Cookies.goodSSLFound(host);
}

// Adapted from the patch for mozTCPSocket error reporting (bug 861196).

function createTCPErrorFromFailedXHR(channel) {
    var status = channel.QueryInterface(Ci.nsIRequest).status;
    var errType;
    var errName;
    if ((status & 0xff0000) === 0x5a0000) { // Security module
        var nsINSSErrorsService = Ci.nsINSSErrorsService;
        var nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
        var errorClass;
        // getErrorClass will throw a generic NS_ERROR_FAILURE if the error code is
        // somehow not in the set of covered errors.
        try {
            errorClass = nssErrorsService.getErrorClass(status);
        } catch (ex) {
            errorClass = 'SecurityProtocol';
        }
        if (errorClass == nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
            errType = 'SecurityCertificate';
        } else {
            errType = 'SecurityProtocol';
        }

// NSS_SEC errors (happen below the base value because of negative vals)
        if ((status & 0xffff) < Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
// The bases are actually negative, so in our positive numeric space, we
// need to subtract the base off our value.
            var nssErr = Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)
                    - (status & 0xffff);
            switch (nssErr) {
                case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
                    errName = 'SecurityExpiredCertificateError';
                    break;
                case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
                    errName = 'SecurityRevokedCertificateError';
                    break;
                    // per bsmith, we will be unable to tell these errors apart very soon,
                    // so it makes sense to just folder them all together already.
                case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
                case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
                case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
                case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
                    errName = 'SecurityUntrustedCertificateIssuerError';
                    break;
                case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
                    errName = 'SecurityInadequateKeyUsageError';
                    break;
                case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
                    errName = 'SecurityCertificateSignatureAlgorithmDisabledError';
                    break;
                default:
                    errName = 'SecurityError';
                    break;
            }
        }
        else {
            var sslErr = Math.abs(nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (status & 0xffff);
            switch (sslErr) {
                case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
                    errName = 'SecurityNoCertificateError';
                    break;
                case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
                    errName = 'SecurityBadCertificateError';
                    break;
                case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
                    errName = 'SecurityUnsupportedCertificateTypeError';
                    break;
                case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
                    errName = 'SecurityUnsupportedTLSVersionError';
                    break;
                case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
                    errName = 'SecurityCertificateDomainMismatchError';
                    break;
                default:
                    errName = 'SecurityError';
                    break;
            }
        }
    }
    else {
        errType = 'Network';
        switch (status) {
// connect to host:port failed
            case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
                errName = 'ConnectionRefusedError';
                break;
                // network timeout error
            case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
                errName = 'NetworkTimeoutError';
                break;
                // hostname lookup failed
            case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
                errName = 'DomainNotFoundError';
                break;
            case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
                errName = 'NetworkInterruptError';
                break;
            default:
                errName = 'NetworkError';
                break;
        }
    }

// XXX we have no TCPError implementation right now because it's really hard to
// do on b2g18. On mozilla-central we want a proper TCPError that ideally
// sub-classes DOMError. Bug 867872 has been filed to implement this and
// contains a documented TCPError.webidl that maps all the error codes we use in
// this file to slightly more readable explanations.
    var error = Cc["@mozilla.org/dom-error;1"].createInstance(Ci.nsIDOMDOMError);
    error.wrappedJSObject.init(errName);
    return errName;
    // XXX: errType goes unused
}


//Certificate testing done before alerting user of https presence
function testCertificate(channel) {
    var secure = false;
    try {
        var secInfo = channel.securityInfo;
        // Print general connection security state
        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
            if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
                    == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
                secure = true;
            }
        }
        if (!secure){
            dump(createTCPErrorFromFailedXHR(channel));
            Cu.reportError("HTTPS Inquirer: testCertificate error: " + err.toString() + "\n");
        }
    }
    catch (err) {
        secure = false;
        Cu.reportError("HTTPS Inquirer: testCertificate error: " + err.toString() + "\n");
    }
    if (httpsinquirer.debug && secure)
        dump("httpsinquirer testCertificate: cert OK (on " +
                channel.URI.host.toLowerCase() + ")\n");
    return secure;
}