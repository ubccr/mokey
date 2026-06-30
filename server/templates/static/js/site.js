document.body.addEventListener('htmx:afterRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (evt.detail.failed && targetError) {
    let msg = "Something bad happened. Please contact site admin";
    if (evt.detail.xhr.status == 400 || evt.detail.xhr.status == 401 || evt.detail.xhr.status == 429 || evt.detail.xhr.status == 500) {
        if (evt.detail.xhr.responseText) {
            msg = evt.detail.xhr.responseText;
        }
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

// Password managers fill inputs without always updating FormData serialization.
// Read .value from the DOM so autofilled username/password are included in HTMX posts.
document.body.addEventListener('htmx:configRequest', function (evt) {
  const elt = evt.detail.elt;
  const form = elt.closest ? elt.closest('form') : null;
  if (!form) {
    return;
  }

  const params = evt.detail.parameters;
  form.querySelectorAll('input, select, textarea').forEach(function (field) {
    if (!field.name || field.disabled) {
      return;
    }
    if (field.type === 'checkbox' || field.type === 'radio') {
      if (field.checked) {
        params[field.name] = field.value;
      }
      return;
    }
    if (field.type === 'file') {
      return;
    }
    params[field.name] = field.value;
  });
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
