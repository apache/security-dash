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
  }

  var forms = document.querySelectorAll(".triage form");
  for (var i = 0; i < forms.length; i++) {
    track(forms[i]);
  }
})();
