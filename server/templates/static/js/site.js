document.body.addEventListener('htmx:afterRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (evt.detail.failed && targetError) {
    msg = "Something bad happened. Please contact site admin";
    if(evt.detail.xhr.status == 400 || evt.detail.xhr.status == 401) {
        msg = evt.detail.xhr.responseText;
    }

    errAlert = document.getElementById(targetError.value)
    errAlert.innerHTML = msg;
    errAlert.style.display = "block";
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
