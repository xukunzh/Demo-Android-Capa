Java.perform(function() {
    console.log("[+] Frida script loaded");

    // List of API calls we're specifically interested in monitoring
    // This allows filtering noise and focusing on relevant operations
    var monitoredApis = [
        "java.io.File.<init>",
        "java.io.FileInputStream.<init>",
        "java.io.FileOutputStream.<init>",
        "android.content.Context.openFileOutput", 
        "android.content.Context.openFileInput",
        "android.content.res.AssetManager.open"
    ];

    // Helper to determine if an API should be logged
    function shouldLogApi(apiName) {
        return monitoredApis.includes(apiName);
    }

    // Hook java.io.File constructor
    var File = Java.use("java.io.File");
    File.$init.overload('java.lang.String').implementation = function(path) {
        var apiName = "java.io.File.<init>";
        
        if (shouldLogApi(apiName)) {
            // Capture stack trace to determine caller context
            var stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            var callSite = "";
            
            // Find app-specific caller in stack trace when possible
            for (var i = 0; i < stack.length; i++) {
                if (stack[i] && stack[i].toString().indexOf("com.example") >= 0) {
                    callSite = stack[i].toString();
                    break;
                }
            }
            
            // Use first frame if no app code found
            if (!callSite && stack.length > 0) {
                callSite = stack[0].toString();
            }
            
            console.log("[File] Creating file: " + path);
            // Output structured data for extractor to parse
            console.log('{"type":"api","name":"' + apiName + '","method":"' + callSite + '","args":{"path":"' + path + '"}}');
        }
        
        return this.$init(path);
    };
    
    // Monitor FileOutputStream
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[FileOutputStream] Opening file output stream: " + path);
        console.log('{"type":"api","name":"java.io.FileOutputStream.<init>","method":"unknown","args":{"path":"' + path + '"}}');
        return this.$init(path);
    };
    
    // Monitor FileInputStream
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[FileInputStream] Opening file input stream: " + path);
        console.log('{"type":"api","name":"java.io.FileInputStream.<init>","method":"unknown","args":{"path":"' + path + '"}}');
        return this.$init(path);
    };
    
    // Monitor Context file operations
    var Context = Java.use("android.content.Context");
    if (Context.openFileOutput) {
        Context.openFileOutput.implementation = function(fileName, mode) {
            console.log("[Context] Opening file output: " + fileName);
            console.log('{"type":"api","name":"android.content.Context.openFileOutput","method":"unknown","args":{"fileName":"' + fileName + '"}}');
            return this.openFileOutput(fileName, mode);
        };
    }
    
    // Monitor Activity lifecycle to confirm script attached successfully
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
        console.log("[Activity] onCreate called");
        this.onCreate(bundle);
    };
    
    try {
        var MainActivity = Java.use("com.example.fridatestjavaapp.MainActivity");  // If app has specific buttons, monitor them directly
        MainActivity.setupFileOperationButton.implementation = function() {
            console.log("[MainActivity] Setting up file operation button");
            this.setupFileOperationButton();
        };
    } catch(e) {
        console.log("Could not monitor setupFileOperationButton: " + e);
    }
    
    // Monitor anonymous inner classes
    try {
        var MainActivity1 = Java.use("com.example.fridatestjavaapp.MainActivity$1");
        MainActivity1.onClick.implementation = function(view) {
            console.log("[MainActivity$1] Click event triggered");
            this.onClick(view);
        };
    } catch(e) {
        console.log("Could not monitor MainActivity$1: " + e);
    }
    
    // ------------------------------
    // NATIVE NETWORK MONITORING
    // ------------------------------
    console.log("[+] Setting up native network monitoring");
    
    try {
        // Monitor socket creation
        Interceptor.attach(Module.findExportByName("libc.so", "socket"), {
            onEnter: function(args) {
                this.domain = args[0].toInt32();
                this.type = args[1].toInt32();
                
                // Get domain name
                var domainName;
                switch(this.domain) {
                    case 0: domainName = "AF_UNSPEC"; break;
                    case 1: domainName = "AF_UNIX"; break;
                    case 2: domainName = "AF_INET"; break;
                    case 10: domainName = "AF_INET6"; break;
                    default: domainName = this.domain.toString();
                }
                
                // Get socket type
                var typeName;
                switch(this.type) {
                    case 1: typeName = "SOCK_STREAM"; break;
                    case 2: typeName = "SOCK_DGRAM"; break;
                    case 3: typeName = "SOCK_RAW"; break;
                    default: typeName = this.type.toString();
                }
                
                console.log("[Native] Creating socket: domain=" + domainName + ", type=" + typeName);
                console.log('{"type":"api","name":"libc.socket","method":"native","args":{"domain":"' + domainName + '","type":"' + typeName + '"}}');
            }
        });
        
        // Monitor connect calls
        Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
            onEnter: function(args) {
                this.sockfd = args[0].toInt32();
                
                // Create unique ID for this event
                var eventId = "connect_" + this.sockfd;
                
                if (!seenEvents[eventId]) {
                    seenEvents[eventId] = true;
                    
                    console.log("[Native] Connect called with sockfd: " + this.sockfd);
                    console.log('{"type":"api","name":"libc.connect","method":"native","args":{"sockfd":"' + this.sockfd + '"}}');
                }
            }
        });
        
        // Monitor send function 
        Interceptor.attach(Module.findExportByName("libc.so", "send"), {
            onEnter: function(args) {
                this.sockfd = args[0].toInt32();
                this.dataSize = args[2].toInt32();
                
                // Create unique ID
                var eventId = "send_" + this.sockfd + "_" + this.dataSize;
                
                if (!seenEvents[eventId]) {
                    seenEvents[eventId] = true;
                    
                    console.log("[Native] Sending " + this.dataSize + " bytes on socket " + this.sockfd);
                    console.log('{"type":"api","name":"libc.send","method":"native","args":{"sockfd":"' + this.sockfd + '","size":"' + this.dataSize + '"}}');
                }
            }
        });
        
        // Monitor recv function
        Interceptor.attach(Module.findExportByName("libc.so", "recv"), {
            onEnter: function(args) {
                this.sockfd = args[0].toInt32();
                this.bufferSize = args[2].toInt32();
                
                // Create unique ID
                var eventId = "recv_" + this.sockfd + "_" + this.bufferSize;
                
                if (!seenEvents[eventId]) {
                    seenEvents[eventId] = true;
                    
                    console.log("[Native] Receiving up to " + this.bufferSize + " bytes on socket " + this.sockfd);
                    console.log('{"type":"api","name":"libc.recv","method":"native","args":{"sockfd":"' + this.sockfd + '","size":"' + this.bufferSize + '"}}');
                }
            }
        });
        
    } catch(e) {
        console.log("Error setting up native network hooks: " + e);
    }
    
    console.log("[+] Monitoring setup complete, waiting for operations...");
});