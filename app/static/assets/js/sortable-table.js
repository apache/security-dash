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

// Sorts the rows of `table.sortable-table` when a header button is clicked.
// A cell sorts by its `data-sort-value`, or else its text; a header with
// `data-sort-type="number"` sorts numerically. Empty cells always sort last.
// The current order is exposed to assistive technology through `aria-sort`.
(function () {
  "use strict";

  function sortValue(row, index) {
    var cell = row.cells[index];
    var value = cell.dataset.sortValue;
    return (value !== undefined ? value : cell.textContent).trim();
  }

  function sortBy(table, th) {
    var headers = th.parentElement.children;
    var index = Array.prototype.indexOf.call(headers, th);
    var numeric = th.dataset.sortType === "number";
    var ascending = th.getAttribute("aria-sort") !== "ascending";
    var tbody = table.tBodies[0];

    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (a, b) {
      var x = sortValue(a, index);
      var y = sortValue(b, index);
      if (x === "" || y === "") {
        return (x === "") - (y === "");
      }
      var order = numeric ? Number(x) - Number(y) : x.localeCompare(y);
      return ascending ? order : -order;
    });
    rows.forEach(function (row) {
      tbody.appendChild(row);
    });

    Array.prototype.forEach.call(headers, function (header) {
      header.removeAttribute("aria-sort");
    });
    th.setAttribute("aria-sort", ascending ? "ascending" : "descending");
  }

  document.querySelectorAll("table.sortable-table").forEach(function (table) {
    table.querySelectorAll("thead th").forEach(function (th) {
      var button = th.querySelector("button");
      if (button) {
        button.addEventListener("click", function () {
          sortBy(table, th);
        });
      }
    });
  });
})();
