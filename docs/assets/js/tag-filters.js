(function () {
  "use strict";

  function displayName(tag) {
    return tag.replace(/\b\w/g, function (letter) {
      return letter.toUpperCase();
    });
  }

  function tagsFor(item) {
    return (item.dataset.tags || "")
      .split(",")
      .map(function (tag) {
        return tag.trim();
      })
      .filter(Boolean);
  }

  document.querySelectorAll("[data-filter-region]").forEach(function (region) {
    var controls = region.querySelector("[data-filter-controls]");
    var items = Array.prototype.slice.call(
      region.querySelectorAll("[data-filter-item]")
    );

    if (!controls || !items.length) {
      return;
    }

    var labels = {};
    var counts = {};

    items.forEach(function (item) {
      tagsFor(item).forEach(function (tag) {
        var key = tag.toLowerCase();
        labels[key] = labels[key] || tag;
        counts[key] = (counts[key] || 0) + 1;
      });
    });

    var tags = Object.keys(labels).sort(function (a, b) {
      return labels[a].localeCompare(labels[b]);
    });

    if (!tags.length) {
      return;
    }

    controls.innerHTML = "";
    controls.setAttribute("role", "group");
    controls.setAttribute(
      "aria-label",
      region.dataset.filterLabel || "Filter this collection"
    );

    function makeButton(key, label, count, active) {
      var button = document.createElement("button");
      var countNode = document.createElement("span");

      button.type = "button";
      button.dataset.filterTag = key;
      button.setAttribute("aria-pressed", active ? "true" : "false");
      button.appendChild(document.createTextNode(label + " "));

      countNode.className = "tag-filter__count";
      countNode.textContent = count;
      countNode.setAttribute("aria-hidden", "true");
      button.appendChild(countNode);

      return button;
    }

    controls.appendChild(makeButton("all", "All", items.length, true));
    tags.forEach(function (key) {
      controls.appendChild(
        makeButton(key, displayName(labels[key]), counts[key], false)
      );
    });

    var status = region.querySelector("[data-filter-status]");

    function applyFilter(key) {
      var visibleCount = 0;

      items.forEach(function (item) {
        var matches =
          key === "all" ||
          tagsFor(item)
            .map(function (tag) {
              return tag.toLowerCase();
            })
            .indexOf(key) !== -1;

        item.hidden = !matches;
        item.style.display = matches ? "" : "none";
        if (matches) {
          visibleCount += 1;
        }
      });

      region.querySelectorAll("[data-filter-group]").forEach(function (group) {
        var hasVisibleItem = Array.prototype.some.call(
          group.querySelectorAll("[data-filter-item]"),
          function (item) {
            return !item.hidden;
          }
        );
        group.hidden = !hasVisibleItem;
        group.style.display = hasVisibleItem ? "" : "none";
      });

      controls.querySelectorAll("button").forEach(function (button) {
        button.setAttribute(
          "aria-pressed",
          button.dataset.filterTag === key ? "true" : "false"
        );
      });

      if (status) {
        status.textContent =
          visibleCount +
          " " +
          (visibleCount === 1 ? "item" : "items") +
          " shown";
      }
    }

    controls.addEventListener("click", function (event) {
      var button = event.target.closest("button[data-filter-tag]");
      if (button) {
        applyFilter(button.dataset.filterTag);
      }
    });

    region.classList.add("filter-region--ready");
    applyFilter("all");
  });
})();
