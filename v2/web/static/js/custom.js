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
        $(this).text("show");
      } else {
        $(this).text("hide");
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


    $('.cvss-radar').each(function() {
        var cvssRadarChart = $(this);
        var myRadarChart = new Chart(cvssRadarChart, {
            type: 'radar',
            data: cvssRadarChart.data("chart"),
            options: {
                legend: {
                  display: false
                },
                scale: {
                  ticks: {
                    min: -1,
                    stepSize: 1,
                    display: false
                  }
                },
                animation: {
                  duration: 0
                },
                tooltips: { enabled: false },
            }
        });
    });


  });