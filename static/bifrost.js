/* Copyright © Playground Global, LLC. All rights reserved. */

/*
 * Util Functions
 */
 
// helper function, because lolJavaScript
function str(s) {
  if ((s !== undefined) && (s !== null) && (s !== "")) {
    return s;
  }
  return "";
}

const globals = {
  IsAdmin: false,
  IsAllowed: false,
  ServiceName: "Bifröst VPN",
  MaxClients: 2,
  DefaultPath: "",
};

Vue.component('waiting', {
  template: "#waiting_modal",
  data: function() {
    return {
      busy: false,
      message: "",
    };
  },
  methods: {
    set: function(msg) {
      this.message = str(msg);
      this.message = this.message != "" ? this.message : "A moment please...";
      this.busy = true;
    },
    clear: function() {
      this.busy = false;
    }
  }
});

Vue.component('error', {
  template: "#error_modal",
  data: function() {
    return {
      "message": "",
      "extra": "",
      "recoverable": false,
    }
  },
  computed: {
    active: function() { return str(this.message) != "" ? true : false; }
  },
  methods: {
    set: function(message, recoverable, extra) {
      this.message = str(message);
      this.extra = str(extra);
      this.recoverable = recoverable ? true : false;
    },
    clear: function() {
      this.message = "";
      this.extra = "";
      this.recoverable = false;
    }
  }
});

const sorry = Vue.component('sorry', {
  template: "#sorry",
  props: [ "globals" ],
});

const users = Vue.component('users', {
  template: "#users",
  props: [ "globals" ],
  data: function() {
    return {
      "users": [],
    };
  },
  methods: {
    "details": function(email) {
      this.$router.push("/users/" + email);
    },
  },
  mounted: function() {
    axios.get("/api/users").then((res) => {
      if (res.data.Artifact != null) {
        this.users = res.data.Artifact.Users;
      } else {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      }
    }).catch((err) => {
      //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      console.log(err);
    });
  },
});

const userWhitelist = Vue.component('user-whitelist', {
  template: "#user-whitelist",
  props: ["globals"],
  data: function() {
    return {
      "users": [],
      "whitelistAdd": "",
    };
  },
  methods: {
    "remove": function(email) {
      axios.delete("/api/whitelist/" + email).then((res) => {
        if (res.data.Artifact != null) {
          console.log(res.data);
          this.users = res.data.Artifact.Users;
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });
    },
    "addUser": function() {
      axios.put("/api/whitelist/" + this.whitelistAdd).then((res) => {
        if (res.data.Artifact != null) {
          console.log(res.data);
          this.users = res.data.Artifact.Users;
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });
      this.whitelistAdd = "";
    },
  },
  mounted: function() {
    axios.get("/api/whitelist").then((res) => {
      if (res.data.Artifact != null) {
        this.users = res.data.Artifact.Users;
      } else {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      }
    }).catch((err) => {
      //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      console.log(err);
    });
  },
});

const settings = Vue.component('settings', {
  template: "#settings",
  props: [ "globals" ],
  mounted: function() {
    axios.get("/api/config").then((res) => {
      if (res.data.Artifact != null) {
        this.serviceName = res.data.Artifact.ServiceName;
        this.clientLimit = res.data.Artifact.ClientLimit;
        this.clientCertDuration = res.data.Artifact.IssuedCertDuration;
        this.whitelistedDomains = res.data.Artifact.WhitelistedDomains;
      } else {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      }
    }).catch((err) => {
      //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      console.log(err);
    });
  },
  data: function() {
    return {
      "serviceName": "",
      "clientLimit": "",
      "clientCertDuration": "",
      "whitelistedDomains": ""
    };
  },
  methods: {
    "cancel": function() {
      this.$router.push(globals.DefaultPath);
    },
    "submit": function() {
      let whitelistedDomains = str(""+this.whitelistedDomains).split(" ").filter(w => w != "");
      let payload = {
        "ServiceName": this.serviceName,
        "ClientLimit": parseInt(this.clientLimit),
        "IssuedCertDuration": parseInt(this.clientCertDuration),
        "WhitelistedDomains": whitelistedDomains,
      };
      if (payload.ClientLimit == NaN) {
        // TODO
        return;
      }
      if (payload.IssuedCertDuration == NaN) {
        // TODO
        return;
      }
      console.log(payload);
      axios.put("/api/config", json=payload).then((res) => {
        //TODO document.location.reload();
        this.$router.push(globals.DefaultPath);
        console.log("done");
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
        this.$router.push(globals.DefaultPath);
      });
    },
  },
});

const devices = Vue.component('devices', {
  template: "#devices",
  props: [ "globals" ],
  data: function() {
    return {
      "certs": [],
      "victim": "",
      "victimDesc": "",
    };
  },
  methods: {
    "revoke": function(fingerprint) {
      this.victimDesc = "";
      for (let c of this.certs) {
        if (c.Fingerprint == fingerprint) {
          this.victimDesc = c.Description;
          break;
        }
      }
      if (this.victimDesc != "") {
        this.victim = fingerprint;
      } else {
        console.log("error, could not find revocation victim");
      }
    },
    "clearRevoke": function() {
      this.victim = "";
      this.victimDesc = "";
    },
    "doRevoke": function(fingerprint) {
      axios.delete("/api/certs/" + fingerprint).then((res) => {
        if (res.data.Artifact != null) {
          this.clearRevoke();
          this.loadCerts();
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
    "addDevice": function() {
      this.$router.push("/newdevice");
    },
    "loadCerts": function() {
      axios.get("/api/certs").then((res) => {
        if (res.data.Artifact != null) {
          this.certs = res.data.Artifact.Certs;
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
  },
  mounted: function() {
    this.loadCerts();
  },
});

const newDevice = Vue.component('new-device', {
  template: "#new-device",
  props: [ "globals" ],
  data: function() {
    return {
      "desc": "",
      "pendingServer": false,
      "ovpn": "",
    };
  },
  computed: {
    "filename": function() {
      return this.desc + ".ovpn";
    },
  },
  methods: {
    "generateCert": function() {
      let payload = { "Description": this.desc };
      this.pendingServer = true;
      axios.post("/api/certs", json=payload).then((res) => {
        if (res.data.Artifact != null) {
          this.ovpn = res.data.Artifact.OVPNDataURL;
        }
        // TODO: error
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
        this.$router.push(globals.DefaultPath);
      });
    },
    "done": function() {
      this.pendingServer = false;
      this.ovpn = "";
      this.desc = "";
      this.$router.push(globals.DefaultPath);
    },
  },
});

const userDetails = Vue.component('user-details', {
  template: "#user-details",
  props: [ "globals", "email" ],
  data: function() {
    return {
      "activeCerts": [],
      "showDeleteConfirm": false,
      "showRevokeConfirm": false,
      "revocationVictim": "",
      "revocationVictimDesc": "",
    };
  },
  methods: {
    "deleteUser": function() {
      this.showDeleteConfirm = true;
    },
    "cancelDeleteUser": function() {
      this.showDeleteConfirm = false;
    },
    "doDeleteUser": function() {
      axios.delete("/api/users/" + this.email).then((res) => {
        if (res.data.Artifact != null) {
          this.$router.replace(this.globals.DefaultPath);
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
    "revoke": function(fingerprint) {
      this.revocationVictimDesc = "";
      for (let c of this.activeCerts) {
        if (c.Fingerprint == fingerprint) {
          this.revocationVictimDesc = c.Description;
          break;
        }
      }
      if (this.revocationVictimDesc != "") {
        this.revocationVictim = fingerprint;
      } else {
        console.log("error, could not find revocation victim");
      }

      this.showRevokeConfirm = true;
    },
    "clearRevoke": function() {
      this.revocationVictim = "";
      this.revocationVictimDesc = "";
      this.showRevokeConfirm = false;
    },
    "doRevoke": function() {
      axios.delete("/api/certs/" + this.revocationVictim).then((res) => {
        if (res.data.Artifact != null) {
          this.clearRevoke();
          this.loadUserCerts();
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
    "loadUserCerts": function() {
      axios.get("/api/users/" + this.email).then((res) => {
        if (res.data.Artifact != null) {
          this.activeCerts = res.data.Artifact.ActiveCerts;
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
  },
  mounted: function() {
    this.loadUserCerts();
  },
});

const totp = Vue.component('password', {
  template: "#totp",
  props: [ "globals" ],
  data: function() {
    return {
      "configured": false,
      "pendingServer": false,
      "imgURL": "",
    };
  },
  mounted: function() {
     axios.get("/api/totp").then((res) => {
      if (res.data.Artifact != null) {
        this.configured = res.data.Artifact.Configured;
      } else {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      }
    }).catch((err) => {
      //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      console.log(err);
    });   
  },
  methods: {
    "reset": function() {
      this.pendingServer = true;
      axios.post("/api/totp").then((res) => {
        if (res.data.Artifact != null) {
          this.imgURL = res.data.Artifact.ImageURL;
        } else {
          //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        }
      }).catch((err) => {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
        console.log(err);
      });   
    },
    "done": function() {
      this.pendingServer = false;
      this.imgURL = "";
      this.configured = true;
    },
  },
});

const router = new VueRouter({
  mode: "history",
  base:  "/",
  routes: [
    { path: "/sorry", component: sorry, props: {globals: globals} },
    { path: "/users", component: users, props: {globals: globals} },
    { path: "/users/:email", component: userDetails, props: (route) => ({ globals: globals, email: route.params.email })},
    { path: "/settings", component: settings, props: {globals: globals} },
    { path: "/devices", component: devices, props: {globals: globals} },
    { path: "/newdevice", component: newDevice, props: {globals: globals} },
    { path: "/password", component: totp, props: {globals: globals} },
  ]
});

Vue.component('navbar', {
  template: "#navbar",
  data: function() {
    return {
      selected: "",
      globals: globals,
    };
  },
  mounted: function() {
    axios.get("/api/init").then((res) => {
      if (res.data.Artifact != null) {
        globals.ServiceName = str(res.data.Artifact.ServiceName);
        globals.IsAdmin = res.data.Artifact.IsAdmin;
        globals.MaxClients = res.data.Artifact.MaxClients;
        globals.DefaultPath = str(res.data.Artifact.DefaultPath);
        globals.IsAllowed = globals.DefaultPath != "/sorry";

        if (str(this.$router.path) == "/" || str(this.$router.path) == "") {
          this.$router.replace(globals.DefaultPath);
        }
        document.title = globals.ServiceName;
      } else {
        //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      }
    }).catch((err) => {
      //TODO error.set("There was an error communicating with the server.", false, "Please try again later.")
      console.log(err);
    });
  },
});

new Vue({el: "#bifrost-root", router: router});