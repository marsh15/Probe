(function(){
var d=document,r=d.documentElement;r.classList.add("js");
function $(s,c){return Array.prototype.slice.call((c||d).querySelectorAll(s));}
var t=d.getElementById("theme");
if(t){t.addEventListener("click",function(){
var dark=r.getAttribute("data-theme")==="dark"||(!r.getAttribute("data-theme")&&matchMedia("(prefers-color-scheme: dark)").matches);
r.setAttribute("data-theme",dark?"light":"dark");t.setAttribute("aria-pressed",String(!dark));});}
$("button.copy").forEach(function(b){b.addEventListener("click",function(){
var s=b.getAttribute("data-copy")||"";
if(navigator.clipboard){navigator.clipboard.writeText(s).then(function(){b.textContent="Copied";});}});});
var rows=$("#checks-table tbody tr"),q=d.getElementById("check-q"),st=d.getElementById("check-status");
function filter(){var text=(q&&q.value||"").toLowerCase(),s=st&&st.value||"";
rows.forEach(function(row){var ok=(!s||row.getAttribute("data-status")===s)&&(!text||row.textContent.toLowerCase().indexOf(text)>=0);
row.hidden=!ok;});}
if(q){q.addEventListener("input",filter);}if(st){st.addEventListener("change",filter);}
var all=d.getElementById("expand-all");
if(all){all.addEventListener("click",function(){var open=all.getAttribute("aria-pressed")!=="true";
$("details.finding").forEach(function(x){x.open=open;});all.setAttribute("aria-pressed",String(open));});}
addEventListener("beforeprint",function(){$("details").forEach(function(x){x.open=true;});});
})();
