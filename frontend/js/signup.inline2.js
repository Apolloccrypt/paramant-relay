
(async function() {
  try {
    var res = await fetch("/api/user/session/verify", {credentials:"include"});
    var d = await res.json();
    if (d.authenticated) {
      document.getElementById("already-email").textContent = d.email;
      document.getElementById("already-signed-in").hidden = false;
      var sf = document.getElementById("signup-form");
      // Dimming this to 0.4 opacity looked disabled but was not: the fields
      // stayed in the tab order, and every label underneath dropped below AA
      // (Lighthouse measured 1.78:1). `inert` takes the form out of the tab
      // order and out of the accessibility tree for real, and the standby
      // class says the same thing without making the words unreadable.
      if (sf) { sf.inert = true; sf.classList.add("is-standby"); }
      document.getElementById("already-signout").addEventListener("click", async function() {
        await fetch("/api/user/logout", {method:"POST",credentials:"include"});
        location.reload();
      });
    }
  } catch (e) {}
})();
