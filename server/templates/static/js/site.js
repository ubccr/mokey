document.body.addEventListener('htmx:afterRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (evt.detail.failed && targetError) {
    msg = "Something bad happened. Please contact site admin";
    if(evt.detail.xhr.status == 400 || evt.detail.xhr.status == 401 || evt.detail.xhr.status == 403 || evt.detail.xhr.status == 429) {
        msg = evt.detail.xhr.responseText;
    }

    errAlert = document.getElementById(targetError.value)
    errAlert.innerHTML = msg;
    errAlert.style.display = "block";
    window.scrollTo(0, 0);
    if(targetError.value.indexOf('dismiss') !== -1) {
        setTimeout(() => {
            errAlert.style.display = "none";
        }, 3000);
    }
  }
});
document.body.addEventListener('htmx:beforeRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (targetError) {
    document.getElementById(targetError.value).style.display = "none";
  }
});

function closeModal(ele) {
    var container = document.getElementById(ele)
    var backdrop = document.getElementById("modal-backdrop")
    var modal = document.getElementById("modal")

    modal.classList.remove("show")
    backdrop.classList.remove("show")

    setTimeout(function() {
        container.removeChild(backdrop)
        container.removeChild(modal)
    }, 200)
}
