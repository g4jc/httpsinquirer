/* ***** BEGIN LICENSE BLOCK ******
 * Version: MPL 1.1 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 *  the License. You may obtain a copy of the License at * http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS" basis,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 *  for the specific language governing rights and limitations under the
 *  License.
 *
 *  The Original Code is HTTPS Finder.
 *
 *  The Initial Developer of the Original Code is Kevin Jacobs.
 *  Portions created by the Initial Developer are Copyright (C) 2011
 *  the Initial Developer. All Rights Reserved.
 *
 *  Contributor(s): Translators - see install.rdf for updated list.
 *
 *  ***** END LICENSE BLOCK *****
 */

"use strict";
Components.utils.import("resource://gre/modules/Services.jsm");

const httpsinquirer_INCLUDE = function(name, targetObj) {
    let LOADER = Cc["@mozilla.org/moz/jssubscript-loader;1"].getService(Ci.mozIJSSubScriptLoader);
    try {
        LOADER.loadSubScript("chrome://httpsinquirer/content/"
            + name + ".js", targetObj);              
    } catch(e) {
        dump("httpsinquirer INCLUDE " + name + ": " + e + "\n");
    }
}

if (!httpsinquirer) var httpsinquirer = {
    prefs: null, //prefs object for httpsinquirer branch
    strings: null, //Strings object for httpsinquirer strings
    history: null, //History observer object (clears results when history is cleared)
    debug: null, //verbose logging bool
    pbs: null //check private browsing status before saving Detection results
};


//Overlay handles most 'browser' code (including alerts except those generated from Detection, importing whitelist, startup/shutdown, etc)
httpsinquirer.Overlay = {
    redirectedTab: [[]], //Tab info for pre-redirect URLs.
    recent: [[]], //Recent auto-redirects used for detecting http->https->http redirect loops. Second subscript holds the tabIndex of the redirect
    lastRecentReset: null, //time counter for detecting redirect loops

    //Window start up - set listeners, read in whitelist, etc
    
      
    init: function(){
        Cu.import("resource://hfShared/hfShared.js", httpsinquirer);
        httpsinquirer.prefs =  Services.prefs.getBranch("extensions.httpsinquirer.");

        httpsinquirer.Cookies = {};
        httpsinquirer.Detect = {};
        httpsinquirer_INCLUDE('Cookies', httpsinquirer.Cookies);
        httpsinquirer_INCLUDE('HTTPSDetect', httpsinquirer.Detect);

        //pref change observer
        httpsinquirer.prefs.QueryInterface(Ci.nsIPrefBranch2);
        httpsinquirer.prefs.addObserver("", this, false);
        
        if(!httpsinquirer.prefs.getBoolPref("enable"))
            return;

        //History observer
        var hs = Cc["@mozilla.org/browser/nav-history-service;1"].
            getService(Ci.nsINavHistoryService);
        hs.addObserver(httpsinquirer.history, false);

        //Used for auto-dismissing alerts (auto-dismiss timer is started when user clicks on a tab, so they don't miss background alerts)
        var container = gBrowser.tabContainer;
        container.addEventListener("TabSelect", httpsinquirer.Overlay.tabChangedListener, false);

        //Listener is used for displaying HTTPS alerts after a page is loaded
        var appcontent = document.getElementById("appcontent");
        if(appcontent)
            appcontent.addEventListener("load", httpsinquirer.Overlay.onPageLoadListener, true);

        //Used to check private browsing status before caching Detection results   
        try {
          // Firefox 20+
          Components.utils.import("resource://gre/modules/PrivateBrowsingUtils.jsm");

          //Hack new per-window private browsing service into existing httpsinquirer.pbs
          httpsinquirer.pbs = {
               privateBrowsingEnabled: null //check private browsing status before saving Detection results
          };
          httpsinquirer.pbs.privateBrowsingEnabled = PrivateBrowsingUtils.isWindowPrivate(window);
          
        } catch(e) {
          // pre Firefox 20 (if you do not have access to a doc. 
          // might use doc.hasAttribute("privatebrowsingmode") then instead)
          try {
            httpsinquirer.pbs = Cc["@mozilla.org/privatebrowsing;1"]
                                .getService(Ci.nsIPrivateBrowsingService);
            
          } catch(e) {
            Components.utils.reportError(e);
          }
        }

        
        //Register HTTP observer for HTTPS Detection   
        httpsinquirer.Detect.register();
        httpsinquirer.Cookies.register();
        
        httpsinquirer.strings = document.getElementById("httpsinquirerStrings");
        if(httpsinquirer.prefs == null || httpsinquirer.strings == null){
            dump("httpsinquirer cannot load Preferences or strings - init() failed\n");
            return;
        }
         
        var installedVersion = httpsinquirer.prefs.getCharPref("version");
        var firstrun = httpsinquirer.prefs.getBoolPref("firstrun");
        httpsinquirer.debug = httpsinquirer.prefs.getBoolPref("debugLogging");

        //Try/catch attempts to recreate db table (in case it has been deleted). Doesn't overwrite though
        try{
            //Create whitelist database
            var file = Cc["@mozilla.org/file/directory_service;1"]
            .getService(Ci.nsIProperties)
            .get("ProfD", Ci.nsIFile);
            file.append("httpsinquirer.sqlite");
            var storageService = Cc["@mozilla.org/storage/service;1"]
            .getService(Ci.mozIStorageService);
            var mDBConn = storageService.openDatabase(file); //Creates db on first run.
            mDBConn.createTable("whitelist", "rule STRING NOT NULL UNIQUE");

        }catch(e){
            //NS_ERROR_FAILURE is thrown when we try to recreate a table (May be too generic though...))
            if(e.name != 'NS_ERROR_FAILURE')
                Cu.reportError("HTTPS Inquirer: initialize error " + e + "\n");
        }
        finally{
            mDBConn.close();
            var currentVersion = httpsinquirer.strings.getString("httpsinquirer.version");
            if (firstrun){
                //First run code
                httpsinquirer.prefs.setBoolPref("firstrun",false);
                httpsinquirer.prefs.setCharPref("version", currentVersion);
            }
            else if (installedVersion != currentVersion && !firstrun){
                //Upgrade code
                httpsinquirer.prefs.setCharPref("version",currentVersion);
                httpsinquirer.Overlay.importWhitelist();
            }
            else //All other startup
                httpsinquirer.Overlay.importWhitelist();
        }
    },

    //Auto-dismiss alert timers are started after the user clicks over to the given tab, so the
    //user doesn't miss background alerts that are dismissed before they switch to the tab.
    tabChangedListener: function(event){
        if(!httpsinquirer.prefs.getBoolPref("dismissAlerts"))
            return;

        var browser = gBrowser.selectedBrowser;
        var alerts = ["httpsinquirer-restart", "httpsinquirer-ssl-enforced", "httpsinquirer-https-found"];

        for(var i=0; i < alerts.length; i++){
            var key = alerts[i];
            //If the tab contains that alert, set a timeout and removeNotification() for the auto-dismiss time.
            if (item = window.getBrowser().getNotificationBox(browser).getNotificationWithValue(key)){
                setTimeout(function(){
                    httpsinquirer.removeNotification(key)
                },httpsinquirer.prefs.getIntPref("alertDismissTime") * 1000);
                return;
            }
        }
    },
    
    /*
     * onPageLoadListener checks for any HTTPS redirect/Detection activity for the tab. If there is something that the user needs to be alerted of,
     * The notification is added. We can't add the notification directly from the Detection callback, because page content still being loaded
     * causes the notifications to be automatically dismissed from time to time. This is basically a method to slow down alerts until the page is ready.
     */
    onPageLoadListener: function(aEvent) {
        var brow = gBrowser.getBrowserForDocument(aEvent.originalTarget);
        var index = gBrowser.getBrowserIndexForDocument(aEvent.originalTarget);
        if(typeof httpsinquirer.Overlay.redirectedTab[index] == "undefined" ||
            typeof httpsinquirer.Overlay.redirectedTab[index][0] == "undefined" ||
            typeof httpsinquirer.Overlay.redirectedTab[index][1] == "undefined" ||
            brow.currentURI.scheme != "https" || brow == null)
            return;

        var tabHost = brow.currentURI.host;
        var storedHost = httpsinquirer.Overlay.redirectedTab[index][1].host;
        if(httpsinquirer.Overlay.getHostWithoutSub(tabHost) != httpsinquirer.Overlay.getHostWithoutSub(storedHost)){
            //Alert was for a previous tab and was not dismissed (page change timed just right before alert was cleared
            httpsinquirer.Overlay.redirectedTab[index] = new Array();
            if(httpsinquirer.debug)
                dump("httpsinquirer resetting alert for tab - host mismatch on " + tabHost  +  " and "  + storedHost + "\n");
            return;
        }

        //If user was redirected - Redirected array holds at [x][0] a bool for whether or not the tab index has been redirected.
        //[x][1] holds a string hostname for the pre-redirect URL.  This is necessary because some sites like Google redirect to
        //encrypted.google.com when you use HTTPS.  We have to remember the old URL so it can be whitelisted from the alert drop down.
        if(httpsinquirer.Overlay.redirectedTab[index][0]){
            if(!httpsinquirer.prefs.getBoolPref("noruleprompt"))
                httpsinquirer.Overlay.alertSSLEnforced(aEvent.originalTarget);
            httpsinquirer.Overlay.redirectedTab[index][0] = false;
        }
    },

    //Return host without subdomain (e.g. input: code.google.com, outpout: google.com)
    getHostWithoutSub: function(fullHost){
        if(typeof fullHost != 'string')
            return "";
        else
            return fullHost.slice(fullHost.indexOf(".") + 1, fullHost.length);
    },

    importWhitelist: function(){
        //Can we get rid of these loops and just reset length? Test in Ubuntu**(wasn't working before without loops)
        for(var i=0; i <  httpsinquirer.results.whitelist.length; i++)
            httpsinquirer.results.whitelist[i] = "";
        httpsinquirer.results.whitelist.length = 0;

        for(i=0; i <  httpsinquirer.results.goodSSL.length; i++)
            httpsinquirer.results.goodSSL[i] = "";
        httpsinquirer.results.goodSSL.length = 0;

        for(i=0; i <  httpsinquirer.results.tempNoAlerts.length; i++)
            httpsinquirer.results.tempNoAlerts[i] = "";
        httpsinquirer.results.tempNoAlerts.length = 0;

        try{
            var file = Cc["@mozilla.org/file/directory_service;1"]
            .getService(Ci.nsIProperties)
            .get("ProfD", Ci.nsIFile);
            file.append("httpsinquirer.sqlite");
            var storageService = Cc["@mozilla.org/storage/service;1"]
            .getService(Ci.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);
            var statement = mDBConn.createStatement("SELECT rule FROM whitelist");

            statement.executeAsync({
                handleResult: function(aResultSet){
                    for (let row = aResultSet.getNextRow(); row; row = aResultSet.getNextRow()){
                        httpsinquirer.results.whitelist.push(row.getResultByName("rule"));
                    }
                },

                handleError: function(anError){
                    dump("httpsinquirer whitelist database error " + anError.message + "\n");
                },

                handleCompletion: function(aReason){
                    //differentiate between permanent and temp whitelist items - permanent items are the first
                    // 'x' entries in the whitelist array. Temp items are added later as x+1....x+n
                    httpsinquirer.results.permWhitelistLength = httpsinquirer.results.whitelist.length;

                    if (aReason != Ci.mozIStorageStatementCallback.REASON_FINISHED)
                        dump("httpsinquirer database error " + aReason.message + "\n");
                    else if(httpsinquirer.prefs.getBoolPref("whitelistChanged"))
                        httpsinquirer.prefs.setBoolPref("whitelistChanged", false);
                }
            });
        }
        catch(e){
            Cu.reportError("HTTPS Inquirer: load whitelist " + e.name + "\n");
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    tempWhitelistDomain: function(hostIn){        
        httpsinquirer.Cookies.restoreDefaultCookiesForHost(hostIn);
        httpsinquirer.results.whitelist.push(hostIn);
    },


    //User clicked "Add to whitelist" from a drop down notification. Save to sqlite and whitelist array.
    whitelistDomain: function(hostIn){
        //Manually remove notification - in Ubuntu it stays up (no error is thrown)
        httpsinquirer.removeNotification('httpsinquirer-https-found');
        httpsinquirer.removeNotification('httpsinquirer-ssl-enforced');
        

        //If no host was passed, get it manually from stored values.
        if(typeof(hostIn) != "string"){
            var hostname;
            if(typeof httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
                typeof httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
                hostname = httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
            else
                hostname = gBrowser.currentURI.host.toLowerCase();

            //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
            //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
            //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
            //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
            //it in for now.  Will look for a better way to do this than the redirectedTab array.
            for(var i=0; i<httpsinquirer.Overlay.redirectedTab.length; i++){
                if(typeof httpsinquirer.Overlay.redirectedTab[i] == "undefined" || typeof httpsinquirer.Overlay.redirectedTab[i][1] == "undefined")
                    hostname = hostname; //do nothing
                else if(httpsinquirer.Overlay.redirectedTab[i][1].host.toLowerCase() == gBrowser.currentURI.host.toLowerCase())
                    hostname = gBrowser.currentURI.host.toLowerCase();
            }
        }
        else if(typeof(hostIn) == "string")
            hostname = hostIn;

        httpsinquirer.Cookies.restoreDefaultCookiesForHost(hostname);

        try{
            var file = Cc["@mozilla.org/file/directory_service;1"]
            .getService(Ci.nsIProperties)
            .get("ProfD", Ci.nsIFile);
            file.append("httpsinquirer.sqlite");
            var storageService = Cc["@mozilla.org/storage/service;1"]
            .getService(Ci.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);

            var statement = mDBConn.createStatement("INSERT INTO whitelist (rule) VALUES (?1)");
            statement.bindStringParameter(0, hostname);
            statement.executeAsync({
                handleResult: function(aResultSet){},

                handleError: function(anError){
                    alert("Error adding rule: " + anError.message);
                    dump("httpsinquirer whitelist rule add error " + anError.message + "\n");
                },
                handleCompletion: function(aReason){
                    if (aReason == Ci.mozIStorageStatementCallback.REASON_FINISHED)
                        if(!httpsinquirer.Overlay.isWhitelisted(hostname) &&
                        !httpsinquirer.pbs.privateBrowsingEnabled){
                        httpsinquirer.results.whitelist.push(hostname);
                    }
                }
            });
        }
        catch(e){
            Cu.reportError("HTTPS Inquirer: addToWhitelist " + e.name + "\n");
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Alert after HTTPS was auto-enforced on a page
    alertSSLEnforced: function(aDocument){
        var browser = gBrowser.getBrowserForDocument(aDocument);

        var host = null;
        try{
            host = gBrowser.currentURI.host;
        }
        catch(e){}

        //Return if a rule has already been saved this session (we just silently enforce)
        if(httpsinquirer.results.tempNoAlerts.indexOf(browser.currentURI.host) != -1)
            return;

        //Append alert if 'noruleeprompt' pref is not enabled, and host is not "". (addon manager, blank page, etc)
        else if(!httpsinquirer.prefs.getBoolPref("noruleprompt") && host != ""){

            var nb = gBrowser.getNotificationBox(gBrowser.getBrowserForDocument(aDocument));
            var saveRuleButtons = [{
                    label: httpsinquirer.strings.getString("httpsinquirer.main.whitelist"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.whitelistKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.whitelistDomain
                },{
                    label: httpsinquirer.strings.getString("httpsinquirer.main.noThanks"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.noThanksKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.redirectNotNow
                },{
                    label: httpsinquirer.strings.getString("httpsinquirer.main.rememberSetting"),
                    accessKey: httpsinquirer.strings.getString("httpsinquirer.main.rememberSettingKey"),
                    popup: null,
                    callback: httpsinquirer.Overlay.writeRule
                }];

            if(httpsinquirer.prefs.getBoolPref("autoforward"))
                nb.appendNotification(httpsinquirer.strings.getString("httpsinquirer.main.autoForwardRulePrompt"),
            "httpsinquirer-ssl-enforced", 'chrome://httpsinquirer/skin/httpsAvailable.png',
            nb.PRIORITY_INFO_HIGH, saveRuleButtons);
            else
                nb.appendNotification(httpsinquirer.strings.getString("httpsinquirer.main.saveRulePrompt"),
            "httpsinquirer-ssl-enforced", 'chrome://httpsinquirer/skin/httpsAvailable.png',
            nb.PRIORITY_INFO_HIGH, saveRuleButtons);

            if(httpsinquirer.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function(){
                    httpsinquirer.removeNotification("httpsinquirer-ssl-enforced")
                },httpsinquirer.prefs.getIntPref("alertDismissTime") * 1000, 'httpsinquirer-ssl-enforced');
        }
    },

    //Check if host is whitelisted (permanently by user, not by us). Checks permanently whitelisted items.
    isPermWhitelisted: function(host){
        for(var i = 0; i < httpsinquirer.results.permWhitelistLength; i++){
            var whitelistItem = httpsinquirer.results.whitelist[i];
            if(whitelistItem == host)
                return true;

            //If rule starts with *., check the end of the hostname (i.e. for *.google.com, check for host ending in .google.com
            else if(whitelistItem.substr(0,2) == "*.")
            //Delete * from rule, compare to last "rule length" chars of the hostname
                if(whitelistItem.replace("*","") == host.substr(host.length -
                    whitelistItem.length + 1,host.length))
                    return true;
        }
        return false;
    },


    //Check if host is whitelisted. Checks permanently whitelisted items and session items.
    isWhitelisted: function(host){
        for(var i=0; i < httpsinquirer.results.whitelist.length; i++){
            var whitelistItem = httpsinquirer.results.whitelist[i];
            if(whitelistItem == host)
                return true;

            //If rule starts with *., check the end of the hostname (i.e. for *.google.com, check for host ending in .google.com
            else if(whitelistItem.substr(0,2) == "*.")
            //Delete * from rule, compare to last "rule length" chars of the hostname
                if(whitelistItem.replace("*","") == host.substr(host.length -
                    whitelistItem.length + 1,host.length))
                    return true;
        }
        return false;
    },

    //Save rule for HTTPS Always. We do a little work here, then pass
    //to the function provided by hfShared (the preference window uses the same code)
    writeRule: function(){
        var eTLDService = Cc["@mozilla.org/network/effective-tld-service;1"]
        .getService(Ci.nsIEffectiveTLDService);

        var topLevel = null;
        try{
            //Try retrieving the pre-redirect host from the redirected array
            topLevel = "." + eTLDService.getPublicSuffix(httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1]);
            var hostname = httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
        }
        catch(e){
            //If that fails (It shouldn't), grab the currentURI
            hostname = gBrowser.currentURI.host.toLowerCase();
            topLevel =  "." + eTLDService.getPublicSuffixFromHost(hostname);
        }

        httpsinquirer.sharedWriteRule(hostname, topLevel, "");
    },

    //Adds to session whitlelist (not database)
    redirectNotNow: function() {
        var hostname = "";
        if(typeof httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
            typeof httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
            hostname = httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
        else
            hostname = gBrowser.currentURI.host.toLowerCase();

        //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
        //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
        //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
        //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
        //it in for now.  Will look for a better way to do this than the redirectedTab array.
        for(var i=0; i<httpsinquirer.Overlay.redirectedTab.length; i++){
            if(typeof httpsinquirer.Overlay.redirectedTab[i] == "undefined" ||
                typeof httpsinquirer.Overlay.redirectedTab[i][1] == "undefined")
                hostname = hostname; //do nothing
            else if(httpsinquirer.Overlay.redirectedTab[i][1].host.toLowerCase() ==
                gBrowser.currentURI.host.toLowerCase())
                hostname = gBrowser.currentURI.host.toLowerCase();
        }
        if(!httpsinquirer.Overlay.isWhitelisted(hostname) && !httpsinquirer.pbs.privateBrowsingEnabled)
            httpsinquirer.Overlay.tempWhitelistDomain(hostname);
    },

    //Auto-redirect to https
    redirectAuto: function(aBrowser, request){
        var sinceLastReset = Date.now() - httpsinquirer.Overlay.lastRecentReset;
        var index = gBrowser.getBrowserIndexForDocument(aBrowser.contentDocument);
        var requestURL = request.URI.asciiSpec.replace("http://", "https://");
        var host = request.URI.host.toLowerCase();

        var redirectLoop = false;
        ///Need to determine if link was clicked, or if reload is automatic
        if(sinceLastReset < 2500 && sinceLastReset > 200){
            for(var i=0; i<httpsinquirer.Overlay.recent.length; i++){
                if(httpsinquirer.Overlay.recent[i][0] == host && httpsinquirer.Overlay.recent[i][1] == index){
                    if(!httpsinquirer.Overlay.isWhitelisted(host) &&
                        !httpsinquirer.pbs.privateBrowsingEnabled)                        
                        httpsinquirer.Overlay.tempWhitelistDomain(host);

                    for(let i = 0; i < httpsinquirer.results.goodSSL.length; i++){
                        if(httpsinquirer.results.goodSSL[i] == host){
                            httpsinquirer.results.goodSSL.splice(i,1);
                            return;
                        }
                    }

                    dump("httpsinquirer redirect loop detected on host " + host + ". Host temporarily whitelisted. Reload time: " + sinceLastReset + "ms\n");
                    redirectLoop = true;
                }
            }
            httpsinquirer.Overlay.recent.length = 0;
        }

        if(httpsinquirer.Detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(),host) && !redirectLoop){
            aBrowser.loadURIWithFlags(requestURL, Components.interfaces.nsIWebNavigation.LOAD_FLAGS_REPLACE_HISTORY);
            httpsinquirer.Overlay.redirectedTab[index] = new Array();
            httpsinquirer.Overlay.redirectedTab[index][0] = true;
            httpsinquirer.Overlay.redirectedTab[index][1] = aBrowser.currentURI;

            httpsinquirer.Overlay.removeFromWhitelist(aBrowser.contentDocument, request.URI.host.toLowerCase());
        }
        else{
            if(httpsinquirer.debug && !redirectLoop)
                dump("Host mismatch, forward blocked (Document: " +
                aBrowser.contentDocument.baseURIObject.host.toLowerCase() +
                " , Detection host: " + host + "\n");
        }

        httpsinquirer.Overlay.recent.push([host,index]);
        httpsinquirer.Overlay.lastRecentReset = Date.now();
    },

    //Manual redirect (user clicked "Yes, go HTTPS")
    redirect: function() {
        var aDocument = gBrowser.contentDocument;
        httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)] = new Array();
        httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][0] = true;

        var ioService = Cc["@mozilla.org/network/io-service;1"]
        .getService(Ci.nsIIOService);

        var uri = gBrowser.getBrowserForDocument(aDocument).currentURI.asciiSpec;
        uri = uri.replace("http://", "https://");

        httpsinquirer.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][1] = ioService.newURI(uri, null, null);
        window.content.wrappedJSObject.location = uri;
    },

    // Removes item from the session whitelist array. This is messy and needs to be fixed.
    // Runes three ways and is called from multiple functions.
    removeFromWhitelist: function(aDocument, host){
        // Check for passed in hostname (if calling function called removeFromWhitelist(null, "xxxxxx.com")
        if(!aDocument && host)
            for(let i=0; i<httpsinquirer.results.whitelist.length; i++){
                if(httpsinquirer.results.whitelist[i] == host){
                    if(httpsinquirer.debug)
                        dump("1 httpsinquirer removing " + httpsinquirer.results.whitelist[i] + " from whitelist\n");
                    httpsinquirer.results.whitelist.splice(i,1);
                }
        }

        // Else, if called as removeFromWhitelist(tab.contentDocument, null) - get the host and remove that from the whitelist
        else if(aDocument && !host){
            var preRedirectHost = gBrowser.getBrowserForDocument(aDocument).currentURI.host;
            for(let i=0; i<httpsinquirer.results.whitelist.length; i++){
                if(httpsinquirer.results.whitelist[i] == preRedirectHost.slice((preRedirectHost.length - httpsinquirer.results.whitelist[i].length),preRedirectHost.length)){
                    if(httpsinquirer.debug)
                        dump("2 httpsinquirer removing " + httpsinquirer.results.whitelist[i] + " from whitelist\n");
                    httpsinquirer.results.whitelist.splice(i,1);

                }
            }
        }

        // Catch for any thing that slipped through... Why is this needed? Maybe if "gBrowser.getBrowserForDocument(aDocument).currentURI.host" (above) fails?
        else
            for(var i=0; i<httpsinquirer.results.whitelist.length; i++)
                if(i > httpsinquirer.results.permWhitelistLength - 1 &&
            httpsinquirer.Overlay.getHostWithoutSub(httpsinquirer.results.whitelist[i]) == httpsinquirer.Overlay.getHostWithoutSub(host)){
            if(httpsinquirer.debug)
                dump("3 httpsinquirer removing " + httpsinquirer.results.whitelist[i] + " from whitelist\n");
            httpsinquirer.results.whitelist.splice(i,1);
        }
    },
    
    openPreferences: function(){
        var prefs = Cc["@mozilla.org/preferences-service;1"]
        .getService(Ci.nsIPrefBranch);
        var instantApply = prefs.getBoolPref("browser.preferences.instantApply");
        var features = "chrome,resizable=no,centerscreen" + (instantApply ?
            ",dialog=no" : ",modal");
        openDialog("chrome://httpsinquirer/content/Preferences.xul", 'preferences', features);
    },

    //User clicked "Clear Session Whitelist" - Reset good and bad cached results, as well as user temporary whitelist.
    resetWhitelist: function(){
        httpsinquirer.popupNotify("HTTPS Inquirer", httpsinquirer.strings.getString("httpsinquirer.overlay.whitelistReset"));

        //Fires re-import of whitelist through observer - Need to remove this since the whitelist is now in JSM (can call directly)
        httpsinquirer.prefs.setBoolPref("whitelistChanged", true);

        httpsinquirer.results.goodSSL.length = 0;
        httpsinquirer.results.goodSSL = [];
        httpsinquirer.results.whitelist.length = 0;
        httpsinquirer.results.whitelist = [];
        httpsinquirer.results.permWhitelistLength = 0;
    },

    //Preference observer
    observe: function(subject, topic, data){
        if (topic != "nsPref:changed")
        return;

        switch(data){
            //Reimport whitelist if user added or removed item
            case "whitelistChanged":
                httpsinquirer.Overlay.importWhitelist();
                break;

            //Remove/add window listener if httpsinquirer is enabled or disabled
        case "enable":
            if(!httpsinquirer.prefs.getBoolPref("enable")){
                try{
                    httpsinquirer.Detect.unregister();
                } catch(e){ /*do nothing - it is already removed if the extension was disabled*/ }

                try{
                    var appcontent = document.getElementById("appcontent");
                    if(appcontent)
                        appcontent.removeEventListener("DOMContentLoaded", httpsinquirer.Overlay.onPageLoadListener, true);
                } catch(e){ /*appcontent may be null*/ }

                gBrowser.tabContainer.removeEventListener("TabSelect", httpsinquirer.Overlay.tabChangedListener, false);

                var hs = Cc["@mozilla.org/browser/nav-history-service;1"].
                    getService(Ci.nsINavHistoryService);
                hs.removeObserver(httpsinquirer.history, "false");
        
                httpsinquirer.Cookies.unregister();
            }
            else if(httpsinquirer.prefs.getBoolPref("enable"))
                httpsinquirer.Overlay.init();
            break;

        case "debugLogging":
            httpsinquirer.debug = httpsinquirer.prefs.getBoolPref("debugLogging");
            break;

        case "dismissAlerts":
            var container = gBrowser.tabContainer;

            if(httpsinquirer.prefs.getBoolPref("dismissAlerts"))
                container.addEventListener("TabSelect", httpsinquirer.Overlay.tabChangedListener, false);
            else
                container.removeEventListener("TabSelect", httpsinquirer.Overlay.tabChangedListener, false);
            break;
    }
},

//Window is shutting down - remove listeners/observers
shutdown: function(){
    try{
        httpsinquirer.prefs.removeObserver("", this);
        httpsinquirer.Detect.unregister();
    }
    catch(e){ /*do nothing - it is already removed if the extension was disabled*/ }

    try{
        var appcontent = document.getElementById("appcontent");
        if(appcontent)
            appcontent.removeEventListener("DOMContentLoaded", httpsinquirer.Overlay.onPageLoadListener, true);
    }
    catch(e){ /*appcontent may be null*/ }


    var container = gBrowser.tabContainer;
    container.removeEventListener("TabSelect", httpsinquirer.Overlay.tabChangedListener, false);

    var hs = Cc["@mozilla.org/browser/nav-history-service;1"].
        getService(Ci.nsINavHistoryService);
    
    try{
        hs.removeObserver(httpsinquirer.history, "false");
    } catch(e) {/*may be null if enabled pref is false*/ }
        
    httpsinquirer.Cookies.unregister();
        
    window.removeEventListener("unload", function(){
        httpsinquirer.Overlay.shutdown();
    }, false);

    window.removeEventListener("load", function(){
        httpsinquirer.Overlay.init();
    }, false);
}
};

httpsinquirer.history = {
onBeginUpdateBatch: function() {},
onEndUpdateBatch: function() {},
onVisit: function(aURI, aVisitID, aTime, aSessionID, aReferringID, aTransitionType) {},
onTitleChanged: function(aURI, aPageTitle) {},
onBeforeDeleteURI: function(aURI) {},
onPageChanged: function(aURI, aWhat, aValue) {},
onDeleteVisits: function(aURI, aVisitTime, aGUID) {},

/*
 *Called when user deletes all instances of a specific URI
 *(warning: Called for each URI in batch operations too)
 */
onDeleteURI: function(aURI){
    let host = aURI.host;

    if(httpsinquirer.results.goodSSL.indexOf(host) != -1)
        for(let i = 0; i < httpsinquirer.results.goodSSL.length; i++){
            if(httpsinquirer.results.goodSSL[i] == host){
                httpsinquirer.results.goodSSL.splice(i,1);
                return;
            }
    }

    else if(httpsinquirer.Overlay.isWhitelisted(host) && !httpsinquirer.Overlay.isPermWhitelisted(host)){
        httpsinquirer.Overlay.removeFromWhitelist(null, host);
    }
},

//Called when all history is cleared.
onClearHistory: function() {
    httpsinquirer.Overlay.resetWhitelist();
},

QueryInterface: XPCOMUtils.generateQI([Ci.nsINavHistoryObserver])
};        



window.addEventListener("load", function(){
httpsinquirer.Overlay.init();
}, false);

window.addEventListener("unload", function(){
httpsinquirer.Overlay.shutdown();
}, false);
