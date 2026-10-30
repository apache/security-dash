// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Reveals the email preview once the PMC picks a decision, and shows the
// sentence that decision produces. The stylesheet keys off the class and the
// data-decision attribute set here, so that a browser with no javascript shows
// the whole form rather than a preview it can never open.
(function () {
  "use strict";

  function setStatus(form, text, isError) {
    var status = form.querySelector(".triage-status");
    if (!status) return;
    status.textContent = text || "";
    status.classList.toggle("triage-error", Boolean(isError));
  }

  function submit(form) {
    var button = form.querySelector('button[type="submit"]');
    setStatus(form, "Submitting decision…", false);
    if (button) button.disabled = true;
    fetch(form.action, {
      method: form.method || "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (response.ok) {
          if (data.redirect) {
            window.location.href = data.redirect;
          } else {
            window.location.reload();
          }
          return;
        }
        setStatus(form, data.message || "Could not submit the decision. Reload the page and try again.", true);
      });
    }).catch(function () {
      setStatus(form, "Could not reach the server. Check your connection and try again.", true);
    }).finally(function () {
      if (button) button.disabled = false;
    });
  }

  function track(form) {
    var chosen = form.querySelector('input[name="action"]:checked');

    // only now is there something able to bring the preview back
    form.classList.add("triage-js");
    if (chosen) {
      // e.g. restored by the browser on a back navigation
      form.dataset.decision = chosen.value;
    }

    form.addEventListener("change", function (event) {
      if (event.target.name === "action") {
        form.dataset.decision = event.target.value;
      }
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      submit(form);
    });
  }

  var forms = document.querySelectorAll(".triage form");
  for (var i = 0; i < forms.length; i++) {
    track(forms[i]);
  }
})();
