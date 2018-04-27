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

const generalError = { Message: "An error occurred in this app.", Extra: "Please reload this page.", Recoverable: false };

const sorry = Vue.component('sorry', {
  template: "#sorry",
  props: [ "globals" ],
});

const users = Vue.component('users', {
  template: "#users",
  props: [ "globals" ],
  data: function() {
    return {
      users: [],
      xhrPending: false,
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    details: function(email) {
      this.$router.push("/users/" + email);
    },
  },
  mounted: function() {
    this.xhrPending = true;
    axios.get("/api/users").then((res) => {
      this.xhrPending = false;
      if (res.data.Artifact) {
        this.users = res.data.Artifact.Users;
      } else {
        this.error = res.data.Error ? res.data.Error : generalError;
      }
    }).catch((err) => {
      this.xhrPending = false;
      this.error = err.response.data.Error ? err.response.data.Error : generalError;
    });
  },
});

const userWhitelist = Vue.component('user-whitelist', {
  template: "#user-whitelist",
  props: ["globals"],
  data: function() {
    return {
      users: [],
      whitelistAdd: "",
      xhrPending: false,
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    remove: function(email) {
      axios.delete("/api/whitelist/" + email).then((res) => {
        if (res.data.Artifact) {
          this.users = res.data.Artifact.Users;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });
    },
    addUser: function() {
      axios.put("/api/whitelist/" + this.whitelistAdd).then((res) => {
        if (res.data.Artifact) {
          this.users = res.data.Artifact.Users;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });
      this.whitelistAdd = "";
    },
  },
  mounted: function() {
    axios.get("/api/whitelist").then((res) => {
      if (res.data.Artifact) {
        this.users = res.data.Artifact.Users;
      } else {
        this.error = res.data.Error ? res.data.Error : generalError;
      }
    }).catch((err) => {
      this.error = err.response.data.Error ? err.response.data.Error : generalError;
    });
  },
});

const settings = Vue.component('settings', {
  template: "#settings",
  props: [ "globals" ],
  mounted: function() {
    axios.get("/api/config").then((res) => {
      if (res.data.Artifact) {
        this.serviceName = res.data.Artifact.ServiceName;
        this.clientLimit = res.data.Artifact.ClientLimit;
        this.clientCertDuration = res.data.Artifact.IssuedCertDuration;
        this.whitelistedDomains = res.data.Artifact.WhitelistedDomains;
      } else {
        this.error = res.data.Error ? res.data.Error : generalError;
      }
    }).catch((err) => {
      this.error = err.response.data.Error ? err.response.data.Error : generalError;
    });
  },
  data: function() {
    return {
      serviceName: "",
      clientLimit: "",
      clientCertDuration: "",
      whitelistedDomains: "",
      xhrPending: false,
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    cancel: function() {
      this.$router.push(globals.DefaultPath);
    },
    submit: function() {
      let whitelistedDomains = str(""+this.whitelistedDomains).split(" ").filter(w => w != "");
      let payload = {
        ServiceName: this.serviceName,
        ClientLimit: parseInt(this.clientLimit),
        IssuedCertDuration: parseInt(this.clientCertDuration),
        WhitelistedDomains: whitelistedDomains,
      };
      if (payload.ClientLimit == NaN) {
        this.error = {Message: "Max clients must be a number.", Extra: "", Recoverable: true};
        return;
      }
      if (payload.IssuedCertDuration == NaN) {
        this.error = {Message: "Refresh period must be a number.", Extra: "", Recoverable: true};
        return;
      }
      axios.put("/api/config", json=payload).then((res) => {
        this.$router.push(globals.DefaultPath);
        document.location.reload();
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });
    },
  },
});

const devices = Vue.component('devices', {
  template: "#devices",
  props: [ "globals" ],
  data: function() {
    return {
      certs: [],
      victim: "",
      victimDesc: "",
      xhrPending: "",
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    revoke: function(fingerprint) {
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
        this.error = {Message: "There was a problem locating that certificate.", Extra: "Try reloading this page.", Recoverable: true};
      }
    },
    clearRevoke: function() {
      this.victim = "";
      this.victimDesc = "";
    },
    doRevoke: function(fingerprint) {
      this.xhrPending = true;
      axios.delete("/api/certs/" + fingerprint).then((res) => {
        this.xhrPending = false;
        this.clearRevoke();
        this.loadCerts();
      }).catch((err) => {
        this.xhrPending = false;
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
    addDevice: function() {
      this.$router.push("/newdevice");
    },
    loadCerts: function() {
      this.xhrPending = true;
      axios.get("/api/certs").then((res) => {
        this.xhrPending = false;
        if (res.data.Artifact) {
          this.certs = res.data.Artifact.Certs;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.xhrPending = false;
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
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
      desc: "",
      pendingServer: false,
      ovpn: "",
      xhrPending: false,
      error: { },
    };
  },
  computed: {
    filename: function() {
      return this.desc + ".ovpn";
    },
  },
  methods: {
    clearError: function() { this.error = { }; },
    generateCert: function() {
      if (str(this.desc) == "") {
        this.error = { Message: "You must enter a description.", Extra: "", Recoverable: true};
        return;
      }
      let payload = { "Description": this.desc };
      this.pendingServer = true;
      axios.post("/api/certs", json=payload).then((res) => {
        if (res.data.Artifact) {
          this.ovpn = res.data.Artifact.OVPNDataURL;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.$router.push(globals.DefaultPath);
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });
    },
    done: function() {
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
      activeCerts: [],
      showDeleteConfirm: false,
      showRevokeConfirm: false,
      revocationVictim: "",
      revocationVictimDesc: "",
      xhrPending: false,
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    deleteUser: function() {
      this.showDeleteConfirm = true;
    },
    cancelDeleteUser: function() {
      this.showDeleteConfirm = false;
    },
    doDeleteUser: function() {
      axios.delete("/api/users/" + this.email).then((res) => {
        if (res.data.Artifact) {
          this.$router.replace(this.globals.DefaultPath);
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
    revoke: function(fingerprint) {
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
        this.error = {Message: "There was a problem locating that certificate.", Extra: "Try reloading this page.", Recoverable: true};
      }

      this.showRevokeConfirm = true;
    },
    clearRevoke: function() {
      this.revocationVictim = "";
      this.revocationVictimDesc = "";
      this.showRevokeConfirm = false;
    },
    doRevoke: function() {
      axios.delete("/api/certs/" + this.revocationVictim).then((res) => {
        if (res.data.Artifact) {
          this.clearRevoke();
          this.loadUserCerts();
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
    loadUserCerts: function() {
      axios.get("/api/users/" + this.email).then((res) => {
        if (res.data.Artifact) {
          this.activeCerts = res.data.Artifact.ActiveCerts;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
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
      configured: false,
      pendingServer: false,
      imgURL: "",
      xhrPending: false,
      error: { },
    };
  },
  mounted: function() {
    axios.get("/api/totp").then((res) => {
      if (res.data.Artifact) {
        this.configured = res.data.Artifact.Configured;
      } else {
        this.error = res.data.Error ? res.data.Error : generalError;
      }
    }).catch((err) => {
      this.error = err.response.data.Error ? err.response.data.Error : generalError;
    });   
  },
  methods: {
    clearError: function() { this.error = { }; },
    reset: function() {
      this.pendingServer = true;
      axios.post("/api/totp").then((res) => {
        if (res.data.Artifact) {
          this.imgURL = res.data.Artifact.ImageURL;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
    done: function() {
      this.pendingServer = false;
      this.imgURL = "";
      this.configured = true;
    },
  },
});

const events = Vue.component('password', {
  template: "#events",
  props: [ "globals" ],
  data: function() {
    return {
      events: [],
      refreshTimer: null,
      before: "",
      xhrPending: false,
      error: { },
    };
  },
  methods: {
    clearError: function() { this.error = { }; },
    loadEvents: function() {
      let url = "/api/events";
      if (this.before != "") {
        url = url + "?before=" + this.before;
      }
      axios.get(url).then((res) => {
        if (res.data.Artifact) {
          this.events = res.data.Artifact.Events;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
    more: function() {
      if (this.events.length > 0) {
        this.stopRefresh();
        this.before = this.events[this.events.length - 1].Timestamp;
        this.startRefresh();
      }
    },
    reset: function() {
        this.stopRefresh();
        this.before = "";
        this.startRefresh();
    },
    startRefresh: function() {
      this.loadEvents();
      this.refreshTimer = setInterval(() => { this.loadEvents(); }, 15000);
    },
    stopRefresh: function() {
      if (this.refreshTimer != null) {
        clearInterval(this.refreshTimer);
        this.refreshTimer = null;
      }
    },
    export: function() {
      axios.get("/api/events?before=all").then((res) => {
        if (res.data.Artifact) {
          this.events = res.data.Artifact.Events;
        } else {
          this.error = res.data.Error ? res.data.Error : generalError;
        }
      }).catch((err) => {
        this.error = err.response.data.Error ? err.response.data.Error : generalError;
      });   
    },
  },
  mounted: function() {
    this.startRefresh();
  },
  beforeDestroy: function() {
    this.stopRefresh();
  },
});

Vue.component('navbar', {
  template: "#navbar",
  data: function() {
    return {
      selected: "",
      globals: globals,
      showIntercept: false,
      xhrPending: false,
      error: { },
    };
  },
  mounted: function() {
    axios.get("/api/init").then((res) => {
      if (res.data.Artifact) {
        globals.ServiceName = str(res.data.Artifact.ServiceName);
        globals.IsAdmin = res.data.Artifact.IsAdmin;
        globals.MaxClients = res.data.Artifact.MaxClients;
        globals.DefaultPath = str(res.data.Artifact.DefaultPath);
        globals.IsAllowed = globals.DefaultPath != "/sorry";

        if (str(this.$router.path) == "/" || str(this.$router.path) == "") {
          this.$router.replace(globals.DefaultPath);
        }
        document.title = globals.ServiceName;
        axios.get("/api/totp").then((res) => {
          if ((res.data.Artifact) && !res.data.Artifact.Configured) {
            this.showIntercept = true;
          }
        }).catch((err) => {
          this.error = err.response.data.Error ? err.response.data.Error : generalError;
        });   
      } else {
        this.error = res.data.Error ? res.data.Error : generalError;
      }
    }).catch((err) => {
      this.error = err.response.data.Error ? err.response.data.Error : generalError;
    });
  },
  methods: {
    clearError: function() { this.error = { }; },
    toTOTP: function() {
      this.$router.replace("/password");
      this.showIntercept = false;
    },
  },
});

Vue.component('waiting-modal', {
  template: "#waiting-modal",
  props: [ "message", "waiting" ],
  computed: {
    displayMessage: function() {
      return str(this.message) != "" ? str(this.message) : "A moment please...";
    },
  },
});

Vue.component('error-modal', {
  template: "#error-modal",
  props: [ "error", "clear" ],
  computed: {
    visible: function() {
      return str(this.error.Message) != "";
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
    { path: "/events", component: events, props: {globals: globals} },
  ],
});

new Vue({el: "#bifrost-root", router: router});