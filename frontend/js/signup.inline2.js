
(async function() {
  try {
    var res = await fetch("/api/user/session/verify", {credentials:"include"});
    var d = await res.json();
    if (d.authenticated) {
      document.getElementById("already-email").textContent = d.email;
      document.getElementById("already-signed-in").hidden = false;
      var sf = document.getElementById("signup-form");
      if (sf) { sf.style.opacity = "0.4"; sf.style.pointerEvents = "none"; }
      document.getElementById("already-signout").addEventListener("click", async function() {
        await fetch("/api/user/logout", {method:"POST",credentials:"include"});
        location.reload();
      });
    }
  } catch (e) {}
})();
