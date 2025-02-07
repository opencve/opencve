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

  });