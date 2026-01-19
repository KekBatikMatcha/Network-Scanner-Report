document.addEventListener("submit", (e) => {
  const form = e.target;
  if(form && form.matches("form")){
    form.classList.add("loading");
    const btn = form.querySelector("button[type=submit]");
    if(btn){
      btn.disabled = true;
      btn.style.opacity = "0.9";
      btn.style.cursor = "wait";
      btn.innerHTML = `<span class="spinner"></span> Running scan...`;
    }
  }
}, true);
