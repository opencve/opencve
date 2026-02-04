var csrftoken = $('meta[name=csrf-token]').attr('content');

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});

function getContrastedColor(str){
    rgb = str.match(/^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/);
    var yiq = ((rgb[1]*299)+(rgb[2]*587)+(rgb[3]*114))/1000;
    return (yiq >= 128) ? '#000' : '#fff';
  }

  $(document).ready(function () {
    function setTagsColor() {
        $(".label-tag").each(function(i) {
            var fontColor = getContrastedColor($(this).css("background-color"));
            $(this).css('color', fontColor);
        });
    }
    $('.sidebar-menu').tree();
    $('[data-toggle="popover"]').popover();
    $('[data-toggle="tooltip"]').tooltip();
    $('.codejson').rainbowJSON({
        maxElements: 0,
        maxDepth: 0,
        json: null,
        bgColor: '#F5FAFF'
    });
    $('.config-toggle').click(function(){
      var conf = $(this).attr("id");
      $("#" + conf + "-table").toggle();
      if ( $("#" + conf + "-table").is(":hidden") ) {
        $(this).text("[+]");
      } else {
        $(this).text("[-]");
      }
    });
    $('#config-all-toggle').click(function(){
      $('.table-configuration').toggle();
    });
    $('#genNew').click(function() {
        var color = '#' + Math.floor(Math.random()*16777215).toString(16);
        $('.preview-tag').css('background-color', color);
        $(".colorpicker").spectrum("set", color);
        setTagsColor();
        return false;
    });
    $(".colorpicker").spectrum({
        preferredFormat: "hex",
        showPalette: true,
        togglePaletteMoreText: 'more',
        togglePaletteLessText: 'less',
        palette: [
            ["#000","#444","#666","#999","#ccc","#eee","#f3f3f3","#fff"],
            ["#f00","#f90","#ff0","#0f0","#0ff","#00f","#90f","#f0f"],
            ["#f4cccc","#fce5cd","#fff2cc","#d9ead3","#d0e0e3","#cfe2f3","#d9d2e9","#ead1dc"],
            ["#ea9999","#f9cb9c","#ffe599","#b6d7a8","#a2c4c9","#9fc5e8","#b4a7d6","#d5a6bd"],
            ["#e06666","#f6b26b","#ffd966","#93c47d","#76a5af","#6fa8dc","#8e7cc3","#c27ba0"],
            ["#c00","#e69138","#f1c232","#6aa84f","#45818e","#3d85c6","#674ea7","#a64d79"],
            ["#900","#b45f06","#bf9000","#38761d","#134f5c","#0b5394","#351c75","#741b47"],
            ["#600","#783f04","#7f6000","#274e13","#0c343d","#073763","#20124d","#4c1130"]
        ]
    });
    $(".colorpicker").on('move.spectrum', function(e, tinycolor) {
        $('.preview-tag').css('background-color', tinycolor.toHexString());
        setTagsColor();
    });
    setTagsColor();
    $('.select2').select2({allowClear: true});
    $('#select2-tags').val($('.select2').data("values")).trigger('change');
    $('.select2-assignee').select2({
      allowClear: true,
      placeholder: 'All assignees',
    });
    $('.select2-status').select2({
      allowClear: true,
      placeholder: 'All statuses',
    });
    $('.select2-view').select2({
      allowClear: true,
      placeholder: 'Select a view',
    });
  // Handle clear event to ensure it works correctly with empty value
  $('#id_assignee').on('select2:clear', function() {
      $(this).val('').trigger('change');
  });

    // Input used to list the user organizations
    $('.select2-organizations').select2({allowClear: false, minimumResultsForSearch: Infinity});
    $('.select2-organizations').on('select2:selecting', function(e) {
        var organization = e.params.args.data.text;
        $.ajax({
            url: CHANGE_ORGANIZATION_URL,
            data: { "organization": organization },
            dataType: 'json',
            type: 'POST',
            success: function(data) {
                if ( data.status == 'ok' ) {
                    document.location.href="/";
                }
            }
        });
    });

    // Fill the query input before opening the Save view modal in CVEs page
    $("#save-view-button").click(function(e) {
      const filter = $("#id_q").val();
      $("#id_query").val(filter);
      $('#modal-save-view').modal('show');
    });

    // Subscriptions handler
    $('.subscribe').click(function() {
        var button = $(this)

        var action = $(button).attr('id').split('_')[0];
        var obj_type = $(button).attr('id').split('_')[1];
        var obj_id = $(button).attr('id').split('_')[2];
        var project_id = $(button).attr('id').split('_')[3];

        $.ajax({
            url: SUBSCRIBE_URL,
            data: { 'action': action, 'obj_type': obj_type, "obj_id": obj_id, "project_id": project_id },
            dataType: 'json',
            type: 'POST',
            success: function(data) {
                if ( data.status == 'ok' ) {
                    $(button).toggleClass('btn-default btn-danger');

                    if ( $(button).text().trim() == 'Subscribe' ) {
                        $(button).html('<i class="fa fa-bell-o"></i> Unsubscribe');
                        $(button).attr("id", $(button).attr('id').replace('subscribe', 'unsubscribe'));
                    } else {
                        $(button).html('<i class="fa fa-bell-o"></i> Subscribe');
                        $(button).attr("id", $(button).attr('id').replace('unsubscribe', 'subscribe'));
                    }
                }
            }
        });
    });


    $('.cvss-radar').each(function () {
        const canvasElement = $(this);
        let radarChartInstance = null;

        const createRadarChart = () => {
            const context = canvasElement[0].getContext("2d");
            radarChartInstance = new Chart(context, {
                type: 'radar',
                data: canvasElement.data("chart"),
                options: {
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            enabled: false
                        }
                    },
                    layout: {
                        padding: {
                            top: 0,
                            bottom: 0
                        }
                    },
                    scales: {
                        r: {
                            suggestedMin: -1,
                            suggestedMax: 2,
                            ticks: {
                                display: false
                            },
                            pointLabels: {
                                padding: 10
                            }
                        }
                    },
                    animation: {
                        duration: 0
                    },
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        };

        // Initial rendering
        createRadarChart();

        // Recreate the graph when tab is changed
        $('a[data-toggle="tab"]').on('shown.bs.tab', (event) => {
            if (canvasElement.is(':visible')) {
                if (radarChartInstance) {
                    radarChartInstance.destroy();
                }
                createRadarChart();
            }
        });
    });

  // Yearly CVEs count (bar)
  if (typeof STATISTICS_CVES_YEARLY_COUNTS !== 'undefined') {
    const ctx_cves_yearly_counts = document.getElementById('statistics_cves_yearly_counts');
    new Chart(ctx_cves_yearly_counts, {
      type: 'bar',
      data: {
        labels: Object.keys(STATISTICS_CVES_YEARLY_COUNTS),
        datasets: [{
          label: 'Total CVEs',
          data: Object.values(STATISTICS_CVES_YEARLY_COUNTS),
          borderWidth: 1,
          borderColor: '#090031',
          backgroundColor: '#382ca3',
        }]
      },
      options: {
        plugins: {
          title: {
            display: true,
            text: 'Yearly CVEs Count'
          },
          legend: {
            display: false
          },
        },
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });

    // Cumulative CVEs count (line)
    const ctx_cves_cumulative_counts = document.getElementById('statistics_cves_cumulative_counts').getContext('2d');

    var gradient = ctx_cves_cumulative_counts.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, 'rgb(5, 3, 45)');
    gradient.addColorStop(1, 'rgba(56, 44, 163, 0.7)');

    new Chart(ctx_cves_cumulative_counts, {
      type: 'line',
      data: {
        labels: Object.keys(STATISTICS_CVES_CUMULATIVE_COUNTS),
        datasets: [{
          label: 'Total CVEs',
          data: Object.values(STATISTICS_CVES_CUMULATIVE_COUNTS),
          borderWidth: 1,
          backgroundColor: gradient,
          fill: true,
        }]
      },
      options: {
        plugins: {
          title: {
            display: true,
            text: 'Cumulative CVEs Count'
          },
          legend: {
            display: false
          },
        },
      }
    });

    // CVSS scores
    const cvssCharts = {
      "cvssV4_0": {
        "rounded": null,
        "categorized": null
      },
      "cvssV3_1": {
        "rounded": null,
        "categorized": null
      },
      "cvssV3_0": {
        "rounded": null,
        "categorized": null
      },
      "cvssV2_0": {
        "rounded": null,
        "categorized": null
      }
    }

    for (metric of Object.keys(cvssCharts)) {

      // CVSS rounded scores (bar)
      let roundedChart = new Chart(document.getElementById('cvss_rounded_scores_' + metric), {
        type: 'bar',
        data: {
          labels: Object.keys(STATISTICS_CVSS_ROUNDED_SCORES[metric]),
          datasets: [{
            label: 'Total CVEs',
            data: Object.values(STATISTICS_CVSS_ROUNDED_SCORES[metric]),
            backgroundColor: [
              'rgb(16, 202, 249)', // 0 (low)
              'rgb(16, 202, 249)', // 1 (low)
              'rgb(16, 202, 249)', // 2 (low)
              'rgb(16, 202, 249)', // 3 (low)
              'rgb(56, 117, 203)', // 4 (medium)
              'rgb(56, 117, 203)', // 5 (medium)
              'rgb(56, 117, 203)', // 6 (medium)
              'rgb(50, 39, 151)', // 7 (hard)
              'rgb(50, 39, 151)', // 8 (hard)
              'rgb(5, 3, 45)', // 9 (critical)
              'rgb(5, 3, 45)' // 10 (critical)
            ],
            borderWidth: 1,
          }]
        },
        options: {
          plugins: {
            legend: {
              display: false
            },
          },
          scales: {
            y: {
              beginAtZero: true
            }
          }
        }
      });
      cvssCharts[metric]["rounded"] = roundedChart;

      // CVSS categorized scores (pie)
      let categorizedChart = new Chart(document.getElementById('cvss_categorized_scores_' + metric), {
        type: 'doughnut',
        data: {
          labels: Object.keys(STATISTICS_CVSS_CATEGORIZED_SCORES[metric]),
          datasets: [{
            data: Object.values(STATISTICS_CVSS_CATEGORIZED_SCORES[metric]),
            backgroundColor: [
              'rgb(16, 202, 249)',
              'rgb(50, 39, 151)',
              'rgb(56, 117, 203)',
              'rgb(5, 3, 45)',
            ],
            hoverOffset: 4
          }]
        },
        options: {
          plugins: {
            legend: {
              display: true,
              position: 'bottom'
            },
          },
        }
      });
      cvssCharts[metric]["categorized"] = categorizedChart;
    }

    // Reload the chart when switching tab
    $('a[data-toggle="tab"]').on('shown.bs.tab', (event) => {
      function resize_chart(version) {
        cvssCharts[version]["rounded"].options.animation = false;
        cvssCharts[version]["categorized"].options.animation = false;
        cvssCharts[version]["rounded"].resize()
        cvssCharts[version]["categorized"].resize()
      }

      const target = $(event.target).attr('href');
      if (['#4_0', '#3_0', '#3_1', '#2_0'].indexOf(target) >= 0) {
        resize_chart('cvssV' + target.substring(1));
      }
    });

    // CVSS Distribution
    const ctx_cvss_distribution = document.getElementById('cvss_distribution');
    const colors = {
      "cvssV2_0": {
        backgroundColor: 'rgba(16, 202, 249, 0.5)',
        borderColor: 'rgb(16, 202, 249)'
      },
      "cvssV3_0": {
        backgroundColor: 'rgba(56, 117, 203, 0.8)',
        borderColor: 'rgb(56, 117, 203)'
      },
      "cvssV3_1": {
        backgroundColor: 'rgba(50, 39, 151, 0.7)',
        borderColor: 'rgb(50, 39, 151)'
      },
      "cvssV4_0": {
        backgroundColor: 'rgba(5, 3, 45, 0.8)',
        borderColor: 'rgb(5, 3, 45)'
      }
    };

    const scatterData = Object.keys(STATISTICS_CVSS_ROUNDED_SCORES).map(version => {
      return {
        label: version.replace('_', '.').toUpperCase(),
        data: Object.entries(STATISTICS_CVSS_ROUNDED_SCORES[version]).map(([x, y]) => ({
          x: parseInt(x),
          y
        })),
        backgroundColor: colors[version].backgroundColor,
        borderColor: colors[version].borderColor
      };
    });

    new Chart(ctx_cvss_distribution, {
      type: 'scatter',
      data: {
        datasets: scatterData,
      },
      options: {
        pointRadius: 4,
        plugins: {
          tooltip: {
            callbacks: {
              label: function(context) {
                return `Score: ${context.raw.x}, CVEs: ${context.raw.y}`;
              }
            }
          }
        },
        scales: {
          x: {
            type: 'linear',
            position: 'bottom',
            title: {
              display: true,
              text: 'CVSS Score'
            },
            ticks: {
              stepSize: 1
            }
          },
          y: {
            title: {
              display: true,
              text: 'Number of CVEs'
            }
          }
        },
        responsive: true
      }
    });

    // Top vendors (horizontal bar)
    const sortedVendors = Object.fromEntries(
      Object.entries(STATISTICS_CVES_TOP_VENDORS).sort(([, a], [, b]) => b - a)
    );
    const ctx_cves_top_vendors = document.getElementById('cves_top_vendors');
    new Chart(ctx_cves_top_vendors, {
      type: 'bar',
      data: {
        labels: Object.keys(sortedVendors),
        datasets: [{
          label: 'Total CVEs',
          data: Object.values(sortedVendors),
          borderWidth: 1,
          borderColor: '#090031',
          backgroundColor: '#382ca3',
        }]
      },
      options: {
        indexAxis: 'y',
        plugins: {
          legend: {
            display: false
          },
        },
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });

    // Top products (horizontal bar)
    const sortedProducts = Object.fromEntries(
      Object.entries(STATISTICS_CVES_TOP_PRODUCTS).sort(([, a], [, b]) => b - a)
    );
    const ctx_cves_top_products = document.getElementById('cves_top_products');
    new Chart(ctx_cves_top_products, {
      type: 'bar',
      data: {
        labels: Object.keys(sortedProducts),
        datasets: [{
          label: 'Total CVEs',
          data: Object.values(sortedProducts),
          borderWidth: 1,
          borderColor: '#090031',
          backgroundColor: '#382ca3',
        }]
      },
      options: {
        indexAxis: 'y',
        plugins: {
          legend: {
            display: false
          },
        },
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }


  function sanitizeText(text) {
      const div = document.createElement('div');
      div.appendChild(document.createTextNode(text));
      return div.innerHTML;
  }

  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
  }


  /*
   Homepage Grid
  */
  const gridStackElement = document.querySelector('.grid-stack');

  if (gridStackElement) {
    const grid = GridStack.init({
      handle: '.drag-widget',
      float: false,
      animate: true,
      cellHeight: 100,
    });

    $(".add-widget").on("click", function () {
      let widgetType = $(this).data("type");
      const content = '<p class="center"><button class="btn btn-default center configure-widget">Configure the widget</button></p>';

      // Find the lowest position
      let maxY = 0;
      grid.engine.nodes.forEach(node => {
        maxY = Math.max(maxY, node.y + node.h);
      });

      const widget = {
          x: 0,
          y: maxY,
          w: 6,
          h: 5,
          id: generateUUID(),
          content: content,
        };

        const element = document.createElement('div');
        element.dataset.type = widgetType;
        element.innerHTML = `
          <div class="grid-stack-item-content box box-primary">
            <div class="box-header">
                <div class="box-title"><i class="fa fa-arrows drag-widget"></i> <span class="box-title-text">New Widget</span></div>
                <div class="box-tools pull-right">
                    <a class="btn btn-box-tool configure-widget"><i class="fa fa-edit"></i></a>
                    <a class="btn btn-box-tool delete-btn"><i class="fa fa-remove"></i></a>
                </div>
            </div>
            <div class="box-body">${content}</div>
          </div>
        `;

        const gridItem = grid.makeWidget(element, widget);

        // Add delete functionality
        element.querySelector('.delete-btn').addEventListener('click', () => {
          grid.removeWidget(element);
        });

        $('#modal-add-widget').modal('hide');

        // Scroll to the new element
        $('html, body').animate({
            scrollTop: $(element).offset().top - 100
        }, 600);
    });

    $("#save-dashboard").on("click", function () {
        const widgets = [];
        const gridItems = grid.engine.nodes;

        gridItems.forEach(node => {
          if (node.el && node.el.dataset.config != undefined) {

            widgets.push({
              x: node.x,
              y: node.y,
              w: node.w,
              h: node.h,
              id: node.id,
              type: node.el.dataset.type,
              config: JSON.parse(node.el.dataset.config),
              title: node.el.dataset.title,
            });
          }
        });

        $.ajax({
            url: SAVE_DASHBOARD_URL,
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify(widgets),
            success: function (response) {
                var $button = $('#save-dashboard');
                var originalText = $button.html();

                // Change button text and style
                $button.html('<i class="fa fa-check"></i> Saved!')
                      .removeClass('btn-default')
                      .addClass('btn-primary');

                // Reset button after 2 seconds
                setTimeout(function() {
                    $button.html(originalText)
                          .removeClass('btn-primary')
                          .addClass('btn-default');
                }, 2000);
            },
            error: function (error) {
                console.error("Error saving dashboard", error);
                var $button = $('#save-dashboard');
                var originalText = $button.html();

                // Show error state
                $button.html('<i class="fa fa-times"></i> Error')
                      .removeClass('btn-default')
                      .addClass('btn-danger');

                // Reset button after 2 seconds
                setTimeout(function() {
                    $button.html(originalText)
                          .removeClass('btn-danger')
                          .addClass('btn-default');
                }, 2000);
            }
        });
    });

    function loadWidgetData(element) {
      var widgetElement = $(element);
      var widgetId = widgetElement.attr("gs-id");

      $.get(LOAD_WIDGET_DATA_URL.replace("$WIDGET_ID$", widgetId), function(data) {
          if (data.html) {
              widgetElement.find(".widget-content").html(data.html);
          } else {
              widgetElement.find(".widget-content").html("<p>An error occurred while loading the widget.</p>");
          }
          widgetElement.find(".widget-loader").hide();
      }).fail(function() {
          widgetElement.find(".widget-content").html("<p>An error occurred while loading the widget.</p>");
          widgetElement.find(".widget-loader").hide();
      });
    }

    function loadDashboard() {
        $.getJSON(LOAD_DASHBOARD_URL, function (data) {
            if (!data.widgets) return;
            const widgets = data.widgets;

            widgets.forEach(widget => {
              const element = document.createElement('div');
              element.dataset.config = JSON.stringify(widget.config);
              element.dataset.type = widget.type;
              element.dataset.title = widget.title;

              element.innerHTML = `
                <div class="grid-stack-item-content box box-primary">
                  <div class="box-header">
                      <div class="box-title"><i class="fa fa-arrows drag-widget" style="font-size: 0.80em;"></i> <span class="box-title-text">${sanitizeText(widget.title)}</span></div>
                      <div class="box-tools pull-right">
                          <a class="btn btn-box-tool configure-widget"><i class="fa fa-edit"></i></a>
                          <a class="btn btn-box-tool delete-btn"><i class="fa fa-remove"></i></a>
                      </div>
                  </div>
                  <div class="box-body">
                    <div class="widget-content"></div>
                    <div class="widget-loader center">
                      <i class="fa fa-spinner fa-spin"></i> Loading...
                    </div>
                  </div>
                </div>
              `;

              grid.makeWidget(element, widget);

              element.querySelector('.delete-btn').addEventListener('click', () => {
                grid.removeWidget(element);
              });

              grid.save(true);
              loadWidgetData(element);
            });
        });
    }
    loadDashboard();

    $(".grid-stack").on("click", ".configure-widget", function () {
      let widgetElement = $(this).closest(".grid-stack-item");
      let widgetConfig = JSON.parse(widgetElement.attr("data-config") || "{}");
      let widgetType = widgetElement.attr("data-type");
      let widgetTitle = widgetElement.attr("data-title");

      $.post(LOAD_WIDGET_CONFIG_URL.replace("$WIDGET_TYPE$", widgetType), JSON.stringify({title: widgetTitle, config: widgetConfig}), function (data) {
        let originalContent = widgetElement.find(".box-body").html();

        // Replace the content with the new one
        widgetElement.find(".box-body").html(`
            <div class="widget-config-container">
                ${data.html}
                <div class="config-buttons text-right mt-2">
                    <button class="btn btn-secondary btn-sm cancel-config">Cancel</button>
                    <button class="btn btn-primary btn-sm save-config">Save</button>
                </div>
            </div>
        `);

        // Cancel button
        widgetElement.find(".cancel-config").on("click", function () {
          widgetElement.find(".box-body").html(originalContent);
        });

        // Confirm button
        widgetElement.find(".save-config").on("click", function () {
          let formData = widgetElement.find("form").serializeArray();
          let config = {};
          formData.forEach(item => config[item.name] = item.value);

          widgetElement.attr("data-title", config.title);
          widgetElement.find(".box-title-text").text(config.title);
          delete config.title;

          // Render the type with the config
          var widgetId = widgetElement.attr("gs-id");
          $.post(RENDER_WIDGET_DATA_URL.replace("$WIDGET_TYPE$", widgetType), {id: widgetId, config: JSON.stringify(config)}, function (renderData) {
            widgetElement.find(".box-body").html(renderData.html);
            widgetElement.attr("data-config", JSON.stringify(renderData.config));
          });

        });

      });
    });
  }

  /*
   CVE List Page - Dynamic Query Builder
  */
  if ($('#dynamic-query-builder').length) {
    const $modal = $('#queryBuilderModal');
    const $builder = $('#dynamic-query-builder');
    const $queryOutput = $('#id_q');
    const $modalQueryDisplay = $('#modal-query-display');
    const queryDisplayPlaceholder = "Query will appear here as you build it...";

    function updateQuery(params) {
        let queryParts = [];

        const addQueryPart = (field, value) => {
            if (value && value.trim()) {
                const trimmedValue = value.trim();

                if (field === 'cve') {
                    queryParts.push(`cve:${trimmedValue.toUpperCase()}`);
                } else if (['description', 'title', 'cwe', 'vendor', 'product', 'userTag', 'project'].includes(field)) {
                    const requiresQuotes = /[\s\:\?\*]/.test(trimmedValue);
                    const formattedValue = requiresQuotes ? `\"${trimmedValue}\"` : trimmedValue;
                    queryParts.push(`${field}:${formattedValue}`);
                }
            }
        };

        // 1. Process static, CWE & repeatable fields
        ['cve', 'description', 'title', 'cwe', 'vendor', 'product', 'userTag', 'project'].forEach(fieldType => {
            $builder.find(`.query-builder-input[data-field="${fieldType}"]`).each(function() {
                addQueryPart(fieldType, $(this).val());
            });
        });

        // 2. Process CVSS
        const cvssVersion = $builder.find('.cvss-version').val();
        const cvssOperator = $builder.find('.cvss-operator').val();
        const cvssScoreRaw = $builder.find('.cvss-score').val().trim();
        if (cvssVersion && cvssOperator && cvssScoreRaw !== '' && !isNaN(parseInt(cvssScoreRaw))) {
            let score = parseInt(cvssScoreRaw);
            if (score >= 0 && score <= 10) {
                queryParts.push(`${cvssVersion}${cvssOperator}${score}`);
            }
        }

        // 3. Process KEV
        const kevChecked = $builder.find('#query-builder-kev').is(':checked');
        if (kevChecked) {
            queryParts.push('kev:true');
        }

        // 4. Process EPSS
        const epssOperator = $builder.find('.epss-operator').val();
        const epssScoreRaw = $builder.find('.epss-score').val().trim();
        if (epssOperator && epssScoreRaw !== '' && !isNaN(parseInt(epssScoreRaw))) {
            let score = parseInt(epssScoreRaw);
            if (score >= 0 && score <= 100) {
                queryParts.push(`epss${epssOperator}${score}`);
            }
        }

        // 5. Process Date Filter
        const dateField = $builder.find('.date-field').val();
        const dateOperator = $builder.find('.date-operator').val();
        const dateValue = $builder.find('.date-value').val().trim();
        if (dateField && dateOperator && dateValue) {
            queryParts.push(`${dateField}${dateOperator}${dateValue}`);
        }

        // Log the final query
        const finalQuery = queryParts.join(' AND ');
        if (finalQuery.trim() === '') {
            $modalQueryDisplay.text(queryDisplayPlaceholder).addClass('text-muted');
        } else {
            $modalQueryDisplay.text(finalQuery).removeClass('text-muted');
        }

        // Enable/disable the Apply button
        const $applyButton = $modal.find('#apply-modal-query');
        if (finalQuery.trim() === '') {
            $applyButton.prop('disabled', true);
        } else {
            $applyButton.prop('disabled', false);
        }
    }

    // Event listener for regular inputs (text, number, non-select2 selects)
    $modal.on('input change', '.query-builder-input:not(.select2-hidden-accessible)', updateQuery);

    // Specific listener for date fields to ensure updates
    $modal.on('input change', '.date-field, .date-operator, .date-value', updateQuery);

    // Initialize Select2 for the initial User Tag select if present
    if ($('.select2-tags-builder').length) {
        const $initialSelect = $('.select2-tags-builder');
        $initialSelect.select2({
            allowClear: true,
            width: '100%',
            placeholder: "Select a tag...",
            dropdownParent: $('#queryBuilderModal')
        });

        // Attach Select2 specific listeners
        $initialSelect.on('select2:select select2:unselect', function (e) {
           updateQuery({ fieldType: 'userTag', value: $(this).val() });
        });
    }

    // Initialize Select2 for the initial Project select if present
    if ($('.select2-project-builder').length) {
      const $initialSelect = $('.select2-project-builder');
      $initialSelect.select2({
          allowClear: true,
          width: '100%',
          placeholder: "Select a project...",
          dropdownParent: $('#queryBuilderModal')
      });

      // Attach Select2 specific listeners
      $initialSelect.on('select2:select select2:unselect', function (e) {
         updateQuery({ fieldType: 'project', value: $(this).val() });
      });
    }

    // Add filter buttons
    let filterCounts = { vendor: 1, product: 1 };
    $modal.on('click', '.add-filter', function() {
        const targetSelector = $(this).data('target');
        const fieldType = $(this).data('field');

        if (!filterCounts.hasOwnProperty(fieldType)) {
            console.warn("Attempted to add filter for unsupported type:", fieldType);
            return;
        }

        filterCounts[fieldType]++;

        const newFilterId = `query-builder-${fieldType}-${filterCounts[fieldType]}`;
        const placeholder = (fieldType === 'vendor' ? 'e.g., apache' : 'e.g., log4j');
        const newFilterHtml = `            <div class="form-group row filter-group mt-2" style="margin-top: 5px;">
                <div class="col-sm-2"></div>
                <div class="col-sm-9">
                    <input type="text" class="form-control query-builder-input" id="${newFilterId}" data-field="${fieldType}" placeholder="${placeholder}">
                </div>
                <div class="col-sm-1">
                    <button type="button" class="btn btn-danger btn-sm remove-filter" title="Remove this filter"><i class="fa fa-minus"></i></button>
                </div>
            </div>`;

        const $newElement = $(newFilterHtml);
        $modal.find(targetSelector).append($newElement);
    });

    // Remove filter buttons
    $modal.on('click', '.remove-filter', function() {
        $(this).closest('.filter-group').remove();
        updateQuery();
    });

    // Reset button
    $modal.on('click', '#reset-query-builder', function() {
        $builder.find('.query-builder-input[type="text"], .query-builder-input[type="number"]').val('');
        $builder.find('select.query-builder-input').each(function() {
             const defaultSelected = $(this).find('option[selected]').val();
             if (defaultSelected) {
                 $(this).val(defaultSelected);
             } else {
                 $(this).prop('selectedIndex', 0);
             }
        });

        // Reset KEV checkbox
        $builder.find('#query-builder-kev').prop('checked', false);

        // Reset EPSS fields
        $builder.find('.epss-operator').prop('selectedIndex', 0);
        $builder.find('.epss-score').val('');

        // Reset Date fields
        $builder.find('.date-field').val('created');
        $builder.find('.date-operator').val('>=');
        $builder.find('.date-value').val('');

        // Remove added filters, keeping the first one
         ['vendor', 'product'].forEach(fieldType => {
             const filterContainer = $builder.find(`#${fieldType}-filters`);
             if (filterContainer.length) {
                filterContainer.find('.filter-group:not(:first)').remove();
                filterContainer.find('.filter-group:first .query-builder-input').val('');
             }
         });
         // Reset the UserTag filter
         const userTagSelect = $builder.find('select.select2-tags-builder[data-field="userTag"]');
         if (userTagSelect.length) {
            userTagSelect.val(null).trigger('change');
         }
         // Reset the Project filter
         const projectSelect = $builder.find('select.select2-project-builder[data-field="project"]');
         if (projectSelect.length) {
            projectSelect.val(null).trigger('change');
         }

        // Reset the modal display field
        $modalQueryDisplay.text(queryDisplayPlaceholder).addClass('text-muted');
        updateQuery();
    });

    // Reset builder fields every time the modal is shown
    $modal.on('show.bs.modal', function () {
        $modal.find('#reset-query-builder').trigger('click');
        filterCounts = { vendor: 1, product: 1 };
    });

    // Apply Query button
    $modal.on('click', '#apply-modal-query', function() {
        const query = $modalQueryDisplay.text();
        if (query && query.trim() !== '' && query !== queryDisplayPlaceholder) {
            const searchUrl = `${CVES_URL}?q=${encodeURIComponent(query)}`;
            window.location.href = searchUrl;
        }
    });
  }

  /*
   CVE Tracking
  */
  (function() {
    // Constants
    const EDIT_ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';

    const STATUS_ORDER = [
        'to_evaluate',
        'pending_review',
        'analysis_in_progress',
        'remediation_in_progress',
        'evaluated',
        'resolved',
        'not_applicable',
        'risk_accepted'
    ];

    const STATUS_BADGE_CLASSES = {
        'to_evaluate': 'badge-secondary',
        'pending_review': 'badge-secondary',
        'analysis_in_progress': 'badge-info',
        'remediation_in_progress': 'badge-info',
        'evaluated': 'badge-success',
        'resolved': 'badge-success',
        'not_applicable': 'badge-warning',
        'risk_accepted': 'badge-warning'
    };

    let currentTippy = null;

    // Helper functions
    function getStatusBadgeClass(statusKey) {
        return STATUS_BADGE_CLASSES[statusKey] || 'badge-secondary';
    }

    function getEditIconSVG() {
        return EDIT_ICON_SVG;
    }

    function sortStatuses(statuses) {
        return statuses.slice().sort(function(a, b) {
            const indexA = STATUS_ORDER.indexOf(a.key);
            const indexB = STATUS_ORDER.indexOf(b.key);
            if (indexA === -1) return 1;
            if (indexB === -1) return -1;
            return indexA - indexB;
        });
    }

    function getUrl(action, projectName, orgName) {
        const endpoint = action === 'assign' ? 'assign-cve-user' : 'update-cve-status';
        return `/org/${orgName}/projects/${projectName}/${endpoint}`;
    }

    function getBadgeSelector(cveId, projectName, badgeType) {
        if (projectName) {
            return `[data-cve-id="${cveId}"][data-project-name="${projectName}"].editable-${badgeType}`;
        }
        return `[data-cve-id="${cveId}"].editable-${badgeType}`;
    }

    function getAnimationTarget(cveId, projectName) {
        const badge = document.querySelector(`[data-cve-id="${cveId}"]${projectName ? `[data-project-name="${projectName}"]` : ''}`);
        if (!badge) return null;

        // Try to find parent row or project-assignment-item
        return badge.closest('tr') || badge.closest('.project-assignment-item');
    }

    // Menu creation functions
    function createAssigneeMenu(cveId, currentAssigneeId, projectName, orgName) {
        const members = window.cveTrackingData.organizationMembers;
        let menuHtml = '<div class="floating-menu">';
        menuHtml += '<div class="floating-menu-title" style="text-align: left;">Select an assignee</div>';

        const isUnassigned = !currentAssigneeId || currentAssigneeId === '';
        const baseAttrs = `data-cve-id="${cveId}" data-assignee-id=""`;
        const attrs = projectName ? `${baseAttrs} data-project-name="${projectName}" data-org-name="${orgName || ''}"` : baseAttrs;

        menuHtml += `<button class="floating-menu-item unassign ${isUnassigned ? 'selected' : ''}" ${attrs}>
                        <i class="fa fa-times"></i> Unassigned
                     </button>`;

        members.forEach(function(member) {
            const isSelected = member.id === currentAssigneeId;
            const baseAttrs = `data-cve-id="${cveId}" data-assignee-id="${member.id}"`;
            const attrs = projectName ? `${baseAttrs} data-project-name="${projectName}" data-org-name="${orgName || ''}"` : baseAttrs;

            menuHtml += `<button class="floating-menu-item ${isSelected ? 'selected' : ''}" ${attrs}>
                            <i class="fa fa-user"></i> ${member.username}
                         </button>`;
        });

        menuHtml += '</div>';
        return menuHtml;
    }

    function createStatusMenu(cveId, currentStatus, projectName, orgName) {
        const statuses = window.cveTrackingData.statusChoices;
        const sortedStatuses = sortStatuses(statuses);

        let menuHtml = '<div class="floating-menu">';
        menuHtml += '<div class="floating-menu-title" style="text-align: left;">Select a status</div>';

        const isNoStatus = !currentStatus || currentStatus === '';
        const baseAttrs = `data-cve-id="${cveId}" data-status=""`;
        const attrs = projectName ? `${baseAttrs} data-project-name="${projectName}" data-org-name="${orgName || ''}"` : baseAttrs;

        menuHtml += `<button class="floating-menu-item ${isNoStatus ? 'selected' : ''}" ${attrs}>
                        <i class="fa fa-times"></i> No status
                     </button>`;

        sortedStatuses.forEach(function(status) {
            const isSelected = status.key === currentStatus;
            const badgeClass = getStatusBadgeClass(status.key);
            const baseAttrs = `data-cve-id="${cveId}" data-status="${status.key}"`;
            const attrs = projectName ? `${baseAttrs} data-project-name="${projectName}" data-org-name="${orgName || ''}"` : baseAttrs;

            menuHtml += `<button class="floating-menu-item ${isSelected ? 'selected' : ''}" ${attrs}>
                            <span class="badge ${badgeClass}" style="margin-right: 8px; font-size: 10px;">${status.label}</span>
                         </button>`;
        });

        menuHtml += '</div>';
        return menuHtml;
    }

    // Badge update functions
    function updateAssigneeBadge(cveId, assigneeId, assigneeUsername, projectName, orgName) {
        const badge = document.querySelector(getBadgeSelector(cveId, projectName, 'assignee'));
        if (!badge) return;

        badge.setAttribute('data-current-assignee', assigneeId || '');
        const editIcon = getEditIconSVG();

        if (assigneeId && assigneeUsername) {
            badge.innerHTML = assigneeUsername + '<span class="edit-icon">' + editIcon + '</span>';
            badge.className = 'editable-assignee badge badge-info';
        } else {
            badge.innerHTML = 'Unassigned<span class="edit-icon">' + editIcon + '</span>';
            badge.className = 'editable-assignee badge badge-secondary';
        }

        if (badge._tippy) {
            badge._tippy.setContent(createAssigneeMenu(cveId, assigneeId, projectName, orgName));
        }
    }

    function updateStatusBadge(cveId, statusKey, statusLabel, projectName, orgName) {
        const badge = document.querySelector(getBadgeSelector(cveId, projectName, 'status'));
        if (!badge) return;

        badge.setAttribute('data-current-status', statusKey || '');
        const editIcon = getEditIconSVG();

        if (statusKey && statusLabel) {
            badge.innerHTML = statusLabel + '<span class="edit-icon">' + editIcon + '</span>';
            const badgeClass = getStatusBadgeClass(statusKey);
            badge.className = `editable-status badge ${badgeClass}`;
        } else {
            badge.innerHTML = 'No status<span class="edit-icon">' + editIcon + '</span>';
            badge.className = 'editable-status badge badge-secondary';
        }

        if (badge._tippy) {
            badge._tippy.setContent(createStatusMenu(cveId, statusKey, projectName, orgName));
        }
    }

    function showSuccessAnimation(cveId, projectName) {
        const target = getAnimationTarget(cveId, projectName);
        if (target) {
            target.style.backgroundColor = '#dafbe1';
            setTimeout(() => {
                target.style.backgroundColor = '';
            }, 1500);
        }
    }

    // API functions
    function assignUser(cveId, assigneeId, projectName, orgName) {
        if (currentTippy) {
            currentTippy.hide();
        }

        const data = {
            cve_id: cveId,
            assignee_id: assigneeId || null
        };

        const url = getUrl('assign', projectName, orgName);

        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateAssigneeBadge(cveId, assigneeId, data.assignee_username, projectName, orgName);
                showSuccessAnimation(cveId, projectName);
            } else {
                console.error('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }

    function updateStatus(cveId, status, projectName, orgName) {
        if (currentTippy) {
            currentTippy.hide();
        }

        const data = {
            cve_id: cveId,
            status: status
        };

        const url = getUrl('update', projectName, orgName);

        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateStatusBadge(cveId, status, data.status, projectName, orgName);
                showSuccessAnimation(cveId, projectName);
            } else {
                console.error('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('An error occurred while updating the status:', error);
        });
    }

    // Initialize badges
    if (window.cveTrackingData) {
        // Initialize assignee badges
        document.querySelectorAll('.editable-assignee').forEach(function(badge) {
            const cveId = badge.getAttribute('data-cve-id');
            const projectName = badge.getAttribute('data-project-name');
            const orgName = badge.getAttribute('data-org-name');
            const currentAssigneeId = badge.getAttribute('data-current-assignee');

            tippy(badge, {
                content: createAssigneeMenu(cveId, currentAssigneeId, projectName, orgName),
                allowHTML: true,
                interactive: true,
                trigger: 'click',
                placement: 'bottom-start',
                animation: 'shift-away',
                theme: 'light-border',
                maxWidth: 250,
                onShow(instance) {
                    if (currentTippy && currentTippy !== instance) {
                        currentTippy.hide();
                    }
                    currentTippy = instance;
                },
                onHide() {
                    currentTippy = null;
                }
            });
        });

        // Initialize status badges
        document.querySelectorAll('.editable-status').forEach(function(badge) {
            const cveId = badge.getAttribute('data-cve-id');
            const projectName = badge.getAttribute('data-project-name');
            const orgName = badge.getAttribute('data-org-name');
            const currentStatus = badge.getAttribute('data-current-status');

            tippy(badge, {
                content: createStatusMenu(cveId, currentStatus, projectName, orgName),
                allowHTML: true,
                interactive: true,
                trigger: 'click',
                placement: 'bottom-start',
                animation: 'shift-away',
                theme: 'light-border',
                maxWidth: 200,
                onShow(instance) {
                    if (currentTippy && currentTippy !== instance) {
                        currentTippy.hide();
                    }
                    currentTippy = instance;
                },
                onHide() {
                    currentTippy = null;
                }
            });
        });

        // Event delegation for menu items
        $(document).on('click', '.floating-menu-item', function(event) {
            const menuItem = $(this)[0];
            const cveId = menuItem.getAttribute('data-cve-id');
            const projectName = menuItem.getAttribute('data-project-name');
            const orgName = menuItem.getAttribute('data-org-name');

            if (menuItem.hasAttribute('data-assignee-id')) {
                const assigneeId = menuItem.getAttribute('data-assignee-id');
                assignUser(cveId, assigneeId, projectName, orgName);
            } else if (menuItem.hasAttribute('data-status')) {
                const status = menuItem.getAttribute('data-status');
                updateStatus(cveId, status, projectName, orgName);
            }

            event.preventDefault();
            event.stopPropagation();
        });

        // Auto-fill query field when a view is selected
        if (window.cveTrackingData && window.cveTrackingData.views) {
            $('#id_view').on('select2:select select2:clear', function(e) {
                const selectedViewId = $(this).val();
                const queryInput = $('#id_query');

                if (selectedViewId) {
                    const selectedView = window.cveTrackingData.views.find(function(view) {
                        return view.id === selectedViewId;
                    });
                    if (selectedView) {
                        queryInput.val(selectedView.query);
                    }
                } else {
                    queryInput.val('');
                }
            });
        }
    }
  })();

  /*
   Vendor/Product Quick Subscription
  */
  if (window.vendorSubscriptionData && window.vendorSubscriptionData.projects.length > 0) {
    let currentSubscriptionTippy = null;

    function createProjectMenu(vendorId, vendorName, productId, productName) {
        const projects = window.vendorSubscriptionData.projects;
        const objType = productId ? 'product' : 'vendor';
        const objId = productId || vendorId;
        const objName = productId ? `${vendorName}$PRODUCT$${productName}` : vendorName;

        let menuHtml = '<div class="floating-menu">';
        menuHtml += '<div class="floating-menu-title">Select a project</div>';

        projects.forEach(function(project) {
            let isSubscribed = false;
            if (objType === 'vendor') {
                isSubscribed = project.subscriptions.vendors.indexOf(vendorName) !== -1;
            } else {
                isSubscribed = project.subscriptions.products.indexOf(objName) !== -1;
            }

            const action = isSubscribed ? 'unsubscribe' : 'subscribe';
            const actionLabel = isSubscribed ? 'Unsubscribe' : 'Subscribe';
            const iconClass = isSubscribed ? 'fa-bell' : 'fa-bell-o';

            menuHtml += `<button class="floating-menu-item ${isSubscribed ? 'selected' : ''}"
                                data-action="${action}"
                                data-obj-type="${objType}"
                                data-obj-id="${objId}"
                                data-project-id="${project.id}">
                            <i class="fa ${iconClass}"></i> ${project.name} <span style="opacity: 0.6; font-size: 11px;">(${actionLabel})</span>
                         </button>`;
        });

        menuHtml += '</div>';
        return menuHtml;
    }

    // Initialize vendor subscription tippy
    document.querySelectorAll('.subscribe-vendor').forEach(function(element) {
        const vendorId = element.getAttribute('data-vendor-id');
        const vendorName = element.getAttribute('data-vendor-name');

        tippy(element, {
            content: createProjectMenu(vendorId, vendorName, null, null),
            allowHTML: true,
            interactive: true,
            trigger: 'click',
            placement: 'bottom-start',
            animation: 'shift-away',
            theme: 'light-border',
            maxWidth: 300,
            onShow(instance) {
                if (currentSubscriptionTippy && currentSubscriptionTippy !== instance) {
                    currentSubscriptionTippy.hide();
                }
                currentSubscriptionTippy = instance;
            },
            onHide() {
                currentSubscriptionTippy = null;
            }
        });
    });

    // Initialize product subscription tippy
    document.querySelectorAll('.subscribe-product').forEach(function(element) {
        const vendorId = element.getAttribute('data-vendor-id');
        const vendorName = element.getAttribute('data-vendor-name');
        const productId = element.getAttribute('data-product-id');
        const productName = element.getAttribute('data-product-name');

        tippy(element, {
            content: createProjectMenu(vendorId, vendorName, productId, productName),
            allowHTML: true,
            interactive: true,
            trigger: 'click',
            placement: 'bottom-start',
            animation: 'shift-away',
            theme: 'light-border',
            maxWidth: 300,
            onShow(instance) {
                if (currentSubscriptionTippy && currentSubscriptionTippy !== instance) {
                    currentSubscriptionTippy.hide();
                }
                currentSubscriptionTippy = instance;
            },
            onHide() {
                currentSubscriptionTippy = null;
            }
        });
    });

    // Event delegation for subscription menu items
    $(document).on('click', '.floating-menu-item[data-obj-type]', function(event) {
        const menuItem = $(this)[0];
        const action = menuItem.getAttribute('data-action');
        const objType = menuItem.getAttribute('data-obj-type');
        const objId = menuItem.getAttribute('data-obj-id');
        const projectId = menuItem.getAttribute('data-project-id');

        subscribeToVendorProduct(action, objType, objId, projectId);

        event.preventDefault();
        event.stopPropagation();
    });

    function subscribeToVendorProduct(action, objType, objId, projectId) {
        // Find the trigger element using the current tippy instance before hiding it
        let triggerElement = null;
        if (currentSubscriptionTippy && currentSubscriptionTippy.reference) {
            triggerElement = currentSubscriptionTippy.reference;
        } else {
            // Fallback: find by data attributes
            if (objType === 'vendor') {
                triggerElement = document.querySelector('.subscribe-vendor[data-vendor-id="' + objId + '"]');
            } else {
                triggerElement = document.querySelector('.subscribe-product[data-product-id="' + objId + '"]');
            }
        }

        if (!triggerElement) {
            console.error('Could not find trigger element');
            return;
        }

        const vendorName = triggerElement.getAttribute('data-vendor-name');
        const productId = triggerElement.getAttribute('data-product-id');
        const productName = triggerElement.getAttribute('data-product-name');

        // Store reference to triggerElement for use in success callback
        const buttonElement = triggerElement;

        // Hide tippy after getting the reference
        if (currentSubscriptionTippy) {
            currentSubscriptionTippy.hide();
        }

        $.ajax({
            url: window.vendorSubscriptionData.url,
            data: {
                'action': action,
                'obj_type': objType,
                'obj_id': objId,
                'project_id': projectId
            },
            dataType: 'json',
            type: 'POST',
            success: function(data) {
                if (data.status === 'ok') {
                    // Update the project subscription status in the data
                    const projects = window.vendorSubscriptionData.projects;
                    const project = projects.find(p => p.id === projectId);
                    if (project) {
                        if (objType === 'vendor') {
                            if (action === 'subscribe') {
                                if (project.subscriptions.vendors.indexOf(vendorName) === -1) {
                                    project.subscriptions.vendors.push(vendorName);
                                }
                            } else {
                                const index = project.subscriptions.vendors.indexOf(vendorName);
                                if (index !== -1) {
                                    project.subscriptions.vendors.splice(index, 1);
                                }
                            }
                        } else {
                            const objName = `${vendorName}$PRODUCT$${productName}`;
                            if (action === 'subscribe') {
                                if (project.subscriptions.products.indexOf(objName) === -1) {
                                    project.subscriptions.products.push(objName);
                                }
                            } else {
                                const index = project.subscriptions.products.indexOf(objName);
                                if (index !== -1) {
                                    project.subscriptions.products.splice(index, 1);
                                }
                            }
                        }
                    }

                    // Update the tippy content with the new subscription state
                    if (buttonElement && buttonElement._tippy) {
                        const vendorId = buttonElement.getAttribute('data-vendor-id');
                        buttonElement._tippy.setContent(createProjectMenu(vendorId, vendorName, productId, productName));
                    }

                    // Recalculate and update the subscription count in the button
                    if (buttonElement) {
                        const projects = window.vendorSubscriptionData.projects;
                        let count = 0;

                        if (objType === 'vendor') {
                            // Count how many projects have this vendor subscribed
                            projects.forEach(function(p) {
                                if (p.subscriptions.vendors.indexOf(vendorName) !== -1) {
                                    count++;
                                }
                            });
                        } else {
                            // Count how many projects have this product subscribed
                            const objName = `${vendorName}$PRODUCT$${productName}`;
                            projects.forEach(function(p) {
                                if (p.subscriptions.products.indexOf(objName) !== -1) {
                                    count++;
                                }
                            });
                        }

                        // Update button text with new count
                        const iconElement = buttonElement.querySelector('i');
                        let buttonText;
                        if (count > 0) {
                            buttonText = 'Subscribed (' + count + ')';
                        } else {
                            buttonText = 'Subscribe';
                        }

                        if (iconElement) {
                            const iconClass = iconElement.className;
                            buttonElement.innerHTML = '<i class="' + iconClass + '"></i> ' + buttonText;
                        } else {
                            // Fallback if icon not found
                            buttonElement.innerHTML = '<i class="fa fa-bell-o"></i> ' + buttonText;
                        }

                        // Add success flash effect
                        buttonElement.classList.add('subscribe-success');
                        setTimeout(function() {
                            buttonElement.classList.remove('subscribe-success');
                        }, 600);
                    }
                }
            },
            error: function(xhr, status, error) {
                console.error('Subscription error:', error);
            }
        });
    }
  }

  // Copy token functionality
  $(document).on('click', '.copy-token-btn', function() {
    var $button = $(this);
    var $tokenInput = $('#new-token');
    var originalText = $button.text();
    var tokenValue = $tokenInput.val();

    // Use modern Clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(tokenValue).then(function() {
        $button.text('Copied!');
        setTimeout(function() {
          $button.text(originalText);
        }, 2000);
      }).catch(function(err) {
        $button.text('Failed');
        setTimeout(function() {
          $button.text(originalText);
        }, 2000);
      });
    } else {
      // Fallback for older browsers
      $tokenInput.select();
      $tokenInput[0].setSelectionRange(0, 99999);
      try {
        document.execCommand('copy');
        $button.text('Copied!');
        setTimeout(function() {
          $button.text(originalText);
        }, 2000);
      } catch (err) {
        $button.text('Failed');
        setTimeout(function() {
          $button.text(originalText);
        }, 2000);
      }
    }
  });

  // Mitre affected products: "See more" / "See less"
  if ($('#mitre-affected-wrapper').length) {
    var $mitreWrapper = $('#mitre-affected-wrapper');
    var $mitreTable = $('#mitre-affected-table');
    var $mitreRows = $mitreTable.find('tbody > tr.mitre-affected-row');
    var mitreLimit = parseInt($mitreWrapper.data('initial-rows') || 5, 10);
    if ($mitreRows.length > mitreLimit) {
      $mitreRows.each(function(i) { if (i >= mitreLimit) { $(this).addClass('mitre-affected-row--overflow'); } });
      $mitreWrapper.addClass('mitre-collapsed');
      $('#mitre-see-more-wrap').show();
    }
    $(document).on('click', '#mitre-see-more-btn', function() {
      var $btn = $(this);
      if ($mitreWrapper.hasClass('mitre-collapsed')) {
        $mitreWrapper.removeClass('mitre-collapsed');
        $btn.text($btn.data('label-less'));
      } else {
        $mitreWrapper.addClass('mitre-collapsed');
        $btn.text($btn.data('label-more'));
      }
    });
  }

  // CVE description: "See more" / "See less" when text is long
  var $descWrapper = $('#cve-description-wrapper');
  var $descText = $('#cve-description-text');
  if ($descWrapper.length && $descText.length) {
    $descWrapper.addClass('cve-description--collapsed');
    var el = $descText[0];
    var hasOverflow = el.scrollHeight > el.clientHeight;
    if (hasOverflow) {
      $('#cve-description-see-more-wrap').show();
    } else {
      $descWrapper.removeClass('cve-description--collapsed');
    }
    $(document).on('click', '#cve-description-see-more-btn', function() {
      var $btn = $(this);
      if ($descWrapper.hasClass('cve-description--collapsed')) {
        $descWrapper.removeClass('cve-description--collapsed');
        $btn.text($btn.data('label-less'));
      } else {
        $descWrapper.addClass('cve-description--collapsed');
        $btn.text($btn.data('label-more'));
      }
    });
  }

  // Onboarding multi-step form
  if ($('#onboarding-form').length) {
    var $form = $('#onboarding-form');
    if (!$form.length) return;
    var searchUrl = $form.attr('data-onboarding-search-url');
    if (!searchUrl) return;

    var MAX_SUBSCRIPTIONS = 5;
    var selectedSubscriptions = new Set();
    var selectedLabels = new Map();
    var PRODUCT_SEP = '$PRODUCT$';

    function getDisplayLabel(value) {
      if (selectedLabels.has(value)) return selectedLabels.get(value);
      if (value.indexOf(PRODUCT_SEP) !== -1) {
        var parts = value.split(PRODUCT_SEP);
        return (parts[0] || '') + ' / ' + (parts[1] || '');
      }
      return value;
    }

    function updateSelectedTags() {
      var $container = $('#onboarding-selected-tags');
      if (!$container.length) return;
      $container.empty();
      selectedSubscriptions.forEach(function(value) {
        var label = $('<span class="onboarding-selected-tag-label">').text(getDisplayLabel(value));
        var $tag = $('<span class="onboarding-selected-tag">')
          .append(label)
          .append(' ')
          .append($('<button type="button" class="onboarding-selected-tag-remove" aria-label="Remove">').text('×'));
        $tag.find('.onboarding-selected-tag-remove').on('click', function() {
          selectedSubscriptions.delete(value);
          selectedLabels.delete(value);
          $('#onboarding-search-results input[type="checkbox"]').each(function() {
            if ($(this).val() === value) $(this).prop('checked', false);
          });
          updateSelectedCount();
        });
        $container.append($tag);
      });
    }

    function showStep(step) {
      $('.onboarding-step-content').hide();
      $('#onboarding-step-' + step).show();
      $('.onboarding-stepper-step').each(function() {
        var n = parseInt($(this).data('step'), 10);
        $(this).removeClass('onboarding-stepper-step-active onboarding-stepper-step-completed');
        if (n < step) $(this).addClass('onboarding-stepper-step-completed');
        else if (n === step) $(this).addClass('onboarding-stepper-step-active');
      });
      $('.onboarding-stepper-connector').removeClass('onboarding-stepper-connector-active');
      $('.onboarding-stepper-connector').slice(0, step - 1).addClass('onboarding-stepper-connector-active');
    }

    function updateSelectedCount() {
      $('#onboarding-selected-count').text(selectedSubscriptions.size + ' / ' + MAX_SUBSCRIPTIONS + ' selected');
      $('#onboarding-selected-count-wrapper').toggle(selectedSubscriptions.size >= 1);
      $('#onboarding-search-results input[type="checkbox"]').each(function() {
        var key = $(this).val();
        var disabled = !selectedSubscriptions.has(key) && selectedSubscriptions.size >= MAX_SUBSCRIPTIONS;
        $(this).prop('disabled', disabled);
      });
      updateSelectedTags();
    }

    function syncHiddenSubscriptions() {
      $('#id_selected_subscriptions').val(JSON.stringify(Array.from(selectedSubscriptions)));
    }

    $('#onboarding-next-1').on('click', function() {
      var org = $('#id_organization').val().trim();
      var project = $('#id_project').val().trim();
      $('#onboarding-org-error, #onboarding-project-error').hide().text('');

      var hasError = false;
      if (!org) {
        $('#onboarding-org-error').text('This field is required.').show();
        hasError = true;
      }
      if (!project) {
        $('#onboarding-project-error').text('This field is required.').show();
        hasError = true;
      }
      if (!hasError) showStep(2);
    });

    $('#id_organization').on('input', function() {
      if ($(this).val().trim()) $('#onboarding-org-error').hide().text('');
    });
    $('#id_project').on('input', function() {
      if ($(this).val().trim()) $('#onboarding-project-error').hide().text('');
    });

    $('#onboarding-prev-2').on('click', function() { showStep(1); });
    $('#onboarding-next-2').on('click', function() {
      syncHiddenSubscriptions();
      showStep(3);
    });
    $('#onboarding-prev-3').on('click', function() { showStep(2); });

    // Prevent Enter from submitting the form unless we're on step 3 (final step)
    $form.on('submit', function(e) {
      if (!$('#onboarding-step-3').is(':visible')) {
        e.preventDefault();
        return false;
      }
    });

    $('#onboarding-search-q').on('keydown', function(e) {
      if (e.which !== 13) return;
      e.preventDefault();
      var q = $(this).val().trim();
      var $msg = $('#onboarding-search-empty-message');
      if (q) {
        $msg.hide().text('');
        $('#onboarding-search-btn').trigger('click');
      } else {
        $msg.text('Please enter text to search for vendors or products.').show();
      }
    });
    $('#onboarding-search-q').on('input', function() {
      $('#onboarding-search-empty-message').hide().text('');
    });

    $('#onboarding-search-btn').on('click', function() {
      var q = $('#onboarding-search-q').val().trim();
      var $vendorsList = $('#onboarding-search-results-vendors-list');
      var $productsList = $('#onboarding-search-results-products-list');
      var $vendorsBlock = $('#onboarding-search-results-vendors');
      var $productsBlock = $('#onboarding-search-results-products');
      var $emptyBlock = $('#onboarding-search-results-empty');

      if (!q) {
        $emptyBlock.html('<p class="text-muted">Enter a search term and click Search.</p>').show();
        $vendorsBlock.add($productsBlock).hide();
        return;
      }

      $emptyBlock.html('<p class="text-muted">Loading...</p>').show();
      $vendorsBlock.add($productsBlock).hide();
      $vendorsList.empty();
      $productsList.empty();

      $.getJSON(searchUrl, { q: q })
        .done(function(data) {
          $vendorsList.empty();
          $productsList.empty();

          if (data.vendors && data.vendors.length) {
            $.each(data.vendors, function(_, v) {
              var $label = $('<label class="checkbox-inline onboarding-checkbox-item">');
              var $cb = $('<input type="checkbox">').attr({ value: v.name, 'data-human-name': v.human_name });
              if (selectedSubscriptions.has(v.name)) $cb.prop('checked', true);
              $cb.on('change', function() {
                if (this.checked) {
                  if (selectedSubscriptions.size >= MAX_SUBSCRIPTIONS) { $cb.prop('checked', false); return; }
                  selectedSubscriptions.add(v.name);
                  selectedLabels.set(v.name, v.human_name);
                } else {
                  selectedSubscriptions.delete(v.name);
                  selectedLabels.delete(v.name);
                }
                updateSelectedCount();
              });
              $label.append($cb).append(' ' + v.human_name);
              $vendorsList.append($label).append('<br>');
            });
          }

          if (data.products && data.products.length) {
            $.each(data.products, function(_, p) {
              var displayName = p.human_name + ' (' + p.vendor + ')';
              var $label = $('<label class="checkbox-inline onboarding-checkbox-item">');
              var $cb = $('<input type="checkbox">').attr({ value: p.vendored_name, 'data-human-name': displayName });
              if (selectedSubscriptions.has(p.vendored_name)) $cb.prop('checked', true);
              $cb.on('change', function() {
                if (this.checked) {
                  if (selectedSubscriptions.size >= MAX_SUBSCRIPTIONS) { $cb.prop('checked', false); return; }
                  selectedSubscriptions.add(p.vendored_name);
                  selectedLabels.set(p.vendored_name, displayName);
                } else {
                  selectedSubscriptions.delete(p.vendored_name);
                  selectedLabels.delete(p.vendored_name);
                }
                updateSelectedCount();
              });
              $label.append($cb).append(' ' + displayName);
              $productsList.append($label).append('<br>');
            });
          }

          var hasVendors = data.vendors && data.vendors.length;
          var hasProducts = data.products && data.products.length;
          if (hasVendors || hasProducts) {
            $emptyBlock.hide();
            if (hasVendors) $vendorsBlock.show();
            if (hasProducts) $productsBlock.show();
          } else {
            $emptyBlock.html('<p class="text-muted">No vendors or products found. Try another term.</p>').show();
            $vendorsBlock.add($productsBlock).hide();
          }
          updateSelectedCount();
        })
        .fail(function() {
          $emptyBlock.html('<p class="text-danger">Search failed. Please try again.</p>').show();
          $vendorsBlock.add($productsBlock).hide();
        });
    });

    function setNotificationFieldsEnabled(enabled) {
      $('#id_notification_email, #id_cvss31_min').prop('disabled', !enabled);
      $('#onboarding-notification-fields').toggleClass('onboarding-notification-fields-disabled', !enabled);
    }
    $('#id_enable_email_notification').on('change', function() {
      setNotificationFieldsEnabled(this.checked);
    });
    setNotificationFieldsEnabled($('#id_enable_email_notification').is(':checked'));

    // Restore selected subscriptions from form (e.g. after validation error)
    // Decode a minimal set of HTML entities without reinterpreting the string as HTML.
    // This avoids using $('<textarea>').html(...).text(), which can reintroduce XSS risks.
    function decodeHtmlEntities(str) {
      if (!str) return str;
      return str
        .replace(/&quot;/g, '"')
        .replace(/&#39;|&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
    }
    var initialSubscriptions = $form.attr('data-initial-subscriptions');
    if (initialSubscriptions) {
      var tmp = decodeHtmlEntities(initialSubscriptions);
      try {
        var arr = JSON.parse(tmp);
        if (Array.isArray(arr)) arr.forEach(function(k) { selectedSubscriptions.add(k); });
      } catch (e) {}
    }
    syncHiddenSubscriptions();
    updateSelectedCount();

    var step2Errors = $('#onboarding-step-2 .text-danger').not('.onboarding-search-empty-message').length;
    var step3Errors = $('#onboarding-step-3 .text-danger').length;
    if (step2Errors) showStep(2);
    else if (step3Errors) showStep(3);
    else showStep(1);
  }
});
