/**
 * Read-only automation flow graph (dagre seed layout + custom stacking + SVG edges).
 */
(function(global) {
  'use strict';

  var NODE_DIMS = {
    trigger: { width: 280, height: 52 },
    schedule: { width: 300, height: 76 },
    condition: { width: 260, height: 52 },
    action: { width: 280, height: 52 },
    placeholder: { width: 220, height: 44 }
  };

  var GROUP_PAD = { left: 20, right: 20 };
  var GROUP_HEADER_HEIGHT = 44;
  var GROUP_INNER_PAD_Y = 16;
  var GROUP_INNER_GAP = 12;
  var GAP_BEFORE_ACTIONS = 44;
  var GAP_AFTER_TRIGGERS = 28;
  var CONDITIONS_GROUP_GAP = 32;
  var MIN_FIT_SCALE = 0.55;
  var MULTI_COND_STEM_FROM_TRIGGERS = 16;
  var MULTI_COND_BUS_STUB = 12;
  var DEFAULT_DATA_SCRIPT_ID = 'automation-flow-graph-data';

  function nodeDims(node) {
    if (node.width && node.height) {
      return { width: node.width, height: node.height };
    }
    return NODE_DIMS[node.kind] || { width: 240, height: 48 };
  }

  function readGraphData(dataScriptId) {
    var el = document.getElementById(dataScriptId || DEFAULT_DATA_SCRIPT_ID);
    if (!el || !el.textContent) return null;
    try {
      return JSON.parse(el.textContent);
    } catch (e) {
      return null;
    }
  }

  function buildDagreGraph(data, childToGroup) {
    var g = new dagre.graphlib.Graph({ compound: false, multigraph: false });
    g.setGraph({
      rankdir: 'TB',
      nodesep: 48,
      ranksep: 64,
      marginx: 24,
      marginy: 24
    });
    g.setDefaultEdgeLabel(function() { return {}; });

    data.nodes.forEach(function(node) {
      var dim = nodeDims(node);
      g.setNode(node.id, {
        width: dim.width,
        height: dim.height,
        kind: node.kind
      });
    });

    data.edges.forEach(function(edge) {
      if (g.hasNode(edge.from) && g.hasNode(edge.to)) {
        var edgeOpts = {};
        if (isEdgeIntoGroup(edge, childToGroup)) {
          edgeOpts.minlen = 1;
        }
        g.setEdge(edge.from, edge.to, edgeOpts);
      }
    });

    dagre.layout(g);
    return g;
  }

  function findGroupByTitle(data, title) {
    var groups = data.groups || [];
    for (var i = 0; i < groups.length; i++) {
      if (groups[i].title === title) return groups[i];
    }
    return null;
  }

  function findGroupsByTitle(data, title) {
    return (data.groups || []).filter(function(group) {
      return group.title === title;
    });
  }

  function measureGraphBounds(data, g, nodeById) {
    var minX = Infinity;
    var minY = Infinity;
    var maxX = -Infinity;
    var maxY = -Infinity;

    g.nodes().forEach(function(nodeId) {
      var layoutNode = g.node(nodeId);
      var meta = nodeById[nodeId];
      if (!layoutNode || !meta) return;
      var dim = nodeDims(meta);
      minX = Math.min(minX, layoutNode.x - dim.width / 2);
      minY = Math.min(minY, layoutNode.y - dim.height / 2);
      maxX = Math.max(maxX, layoutNode.x + dim.width / 2);
      maxY = Math.max(maxY, layoutNode.y + dim.height / 2);
    });

    (data.groups || []).forEach(function(group) {
      var childIds = group.children || [];
      var frameMinX = Infinity;
      var frameMinY = Infinity;
      var frameMaxX = -Infinity;
      var frameMaxY = -Infinity;
      childIds.forEach(function(childId) {
        var layoutNode = g.node(childId);
        var meta = nodeById[childId];
        if (!layoutNode || !meta) return;
        var dim = nodeDims(meta);
        var left = layoutNode.x - dim.width / 2;
        var top = layoutNode.y - dim.height / 2;
        frameMinX = Math.min(frameMinX, left);
        frameMinY = Math.min(frameMinY, top);
        frameMaxX = Math.max(frameMaxX, left + dim.width);
        frameMaxY = Math.max(frameMaxY, top + dim.height);
      });
      if (isFinite(frameMinX)) {
        minX = Math.min(minX, frameMinX - GROUP_PAD.left);
        minY = Math.min(minY, frameMinY - GROUP_HEADER_HEIGHT - GROUP_INNER_PAD_Y);
        maxX = Math.max(maxX, frameMaxX + GROUP_PAD.right);
        maxY = Math.max(maxY, frameMaxY + GROUP_INNER_PAD_Y);
      }
    });

    var padding = 24;
    return {
      width: maxX - minX + padding * 2,
      height: maxY - minY + padding * 2,
      offsetX: minX - padding,
      offsetY: minY - padding
    };
  }

  function bezierPath(x1, y1, x2, y2) {
    var midY = (y1 + y2) / 2;
    return 'M' + x1 + ',' + y1 +
      ' C' + x1 + ',' + midY + ' ' + x2 + ',' + midY + ' ' + x2 + ',' + y2;
  }

  function busFanoutPath(fromPoint, targetPoints, stemGap) {
    var busY = fromPoint.y + stemGap;
    var xs = targetPoints.map(function(t) { return t.x; });
    xs.push(fromPoint.x);
    var minX = Math.min.apply(null, xs);
    var maxX = Math.max.apply(null, xs);
    var sorted = targetPoints.slice().sort(function(a, b) {
      return a.x - b.x;
    });
    var parts = [
      'M', fromPoint.x, fromPoint.y,
      'L', fromPoint.x, busY,
      'L', minX, busY,
      'L', maxX, busY
    ];
    sorted.forEach(function(target) {
      parts.push('M', target.x, busY, 'L', target.x, target.y);
    });
    return parts.join(' ');
  }

  function busMergePathFromFrames(sources, targetPoint, stubGap) {
    var busY = Math.max.apply(null, sources.map(function(s) { return s.y; })) + stubGap;
    var sorted = sources.slice().sort(function(a, b) {
      return a.x - b.x;
    });
    var xs = sources.map(function(s) { return s.x; });
    xs.push(targetPoint.x);
    var minX = Math.min.apply(null, xs);
    var maxX = Math.max.apply(null, xs);
    var parts = [];
    sorted.forEach(function(source) {
      parts.push('M', source.x, source.y, 'L', source.x, busY);
    });
    parts.push('M', minX, busY, 'L', maxX, busY);
    parts.push('L', targetPoint.x, busY, 'L', targetPoint.x, targetPoint.y);
    return parts.join(' ');
  }

  function appendSvgPath(svg, d) {
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('class', 'automation-flow-graph__edge');
    path.setAttribute('d', d);
    svg.appendChild(path);
  }

  function layoutX(x, bounds) {
    return x - bounds.offsetX;
  }

  function layoutY(y, bounds) {
    return y - bounds.offsetY;
  }

  function createNodeElement(node, layoutNode, bounds) {
    var dim = nodeDims(node);
    var el = document.createElement('div');
    el.className = 'automation-flow-node automation-flow-node--' + node.kind;
    if (node.muted) {
      el.classList.add('automation-flow-node--muted');
    }
    el.setAttribute('data-node-id', node.id);
    el.style.width = dim.width + 'px';
    el.style.height = dim.height + 'px';
    el.style.left = (layoutX(layoutNode.x, bounds) - dim.width / 2) + 'px';
    el.style.top = (layoutY(layoutNode.y, bounds) - dim.height / 2) + 'px';

    if (node.icon) {
      var iconWrap = document.createElement('div');
      iconWrap.className = 'automation-flow-node__icon';
      var icon = document.createElement('i');
      icon.className = 'fa ' + node.icon;
      iconWrap.appendChild(icon);
      el.appendChild(iconWrap);
    }

    var content = document.createElement('div');
    content.className = 'automation-flow-node__content';
    var title = document.createElement('div');
    title.className = 'automation-flow-node__title';
    title.textContent = node.title;
    content.appendChild(title);
    if (node.subtitle) {
      var subtitle = document.createElement('div');
      subtitle.className = 'automation-flow-node__subtitle';
      subtitle.textContent = node.subtitle;
      content.appendChild(subtitle);
    }
    el.appendChild(content);
    return el;
  }

  function childHeight(childId, nodeById, elementMap) {
    var meta = nodeById[childId];
    if (!meta) return NODE_DIMS.action.height;
    var el = elementMap && elementMap[childId];
    if (el && el.offsetHeight) return el.offsetHeight;
    return nodeDims(meta).height;
  }

  function triggersGroupFrameBottom(group, g, nodeById, elementMap) {
    var maxBottom = -Infinity;
    group.children.forEach(function(childId) {
      var layoutNode = g.node(childId);
      if (!layoutNode) return;
      var h = childHeight(childId, nodeById, elementMap);
      maxBottom = Math.max(maxBottom, layoutNode.y + h / 2);
    });
    if (!isFinite(maxBottom)) return null;
    return maxBottom + GROUP_INNER_PAD_Y;
  }

  function triggersGroupCenterX(group, g) {
    var sum = 0;
    var count = 0;
    group.children.forEach(function(childId) {
      var layoutNode = g.node(childId);
      if (!layoutNode) return;
      sum += layoutNode.x;
      count += 1;
    });
    return count ? sum / count : 0;
  }

  function groupContentTop(group, g, nodeById, elementMap) {
    var minTop = Infinity;
    (group.children || []).forEach(function(childId) {
      var layout = g.node(childId);
      if (!layout) return;
      var h = childHeight(childId, nodeById, elementMap);
      minTop = Math.min(minTop, layout.y - h / 2);
    });
    return isFinite(minTop) ? minTop : 0;
  }

  function layoutStackedGroup(g, group, nodeById, elementMap, centerX, frameTop) {
    var y = frameTop + GROUP_HEADER_HEIGHT + GROUP_INNER_PAD_Y;
    (group.children || []).forEach(function(childId, index) {
      var layout = g.node(childId);
      if (!layout) return;
      var h = childHeight(childId, nodeById, elementMap);
      layout.x = centerX;
      layout.y = y + h / 2;
      y += h;
      if (index < group.children.length - 1) {
        y += GROUP_INNER_GAP;
      }
    });
  }

  function estimateGroupWidth(group, nodeById, elementMap) {
    var maxChildW = NODE_DIMS.condition.width;
    (group.children || []).forEach(function(childId) {
      var el = elementMap && elementMap[childId];
      if (el && el.offsetWidth) {
        maxChildW = Math.max(maxChildW, el.offsetWidth);
      }
    });
    return maxChildW + GROUP_PAD.left + GROUP_PAD.right;
  }

  function estimateGroupHeight(group, nodeById, elementMap) {
    var height = GROUP_HEADER_HEIGHT + GROUP_INNER_PAD_Y * 2;
    (group.children || []).forEach(function(childId, index) {
      height += childHeight(childId, nodeById, elementMap);
      if (index < group.children.length - 1) {
        height += GROUP_INNER_GAP;
      }
    });
    return height;
  }

  function layoutConditionsGroupsRow(data, g, nodeById, elementMap, graphCenterX, frameTop) {
    var groups = findGroupsByTitle(data, 'Conditions');
    if (!groups.length) return frameTop;

    var specs = groups.map(function(group) {
      return {
        group: group,
        width: estimateGroupWidth(group, nodeById, elementMap),
        height: estimateGroupHeight(group, nodeById, elementMap)
      };
    });

    var totalWidth = 0;
    specs.forEach(function(spec, index) {
      totalWidth += spec.width;
      if (index < specs.length - 1) totalWidth += CONDITIONS_GROUP_GAP;
    });

    var cursorX = graphCenterX - totalWidth / 2;
    var maxBottom = frameTop;

    specs.forEach(function(spec, index) {
      var centerX = cursorX + spec.width / 2;
      layoutStackedGroup(g, spec.group, nodeById, elementMap, centerX, frameTop);
      cursorX += spec.width;
      if (index < specs.length - 1) cursorX += CONDITIONS_GROUP_GAP;
      maxBottom = Math.max(maxBottom, frameTop + spec.height);
    });

    return maxBottom;
  }

  function maxConditionExitBottom(data, g, nodeById, childToGroup) {
    var maxBottom = -Infinity;
    data.edges.forEach(function(edge) {
      if (!isEdgeIntoGroup(edge, childToGroup)) return;
      var fromLayout = g.node(edge.from);
      var fromMeta = nodeById[edge.from];
      if (!fromLayout || !fromMeta) return;
      maxBottom = Math.max(
        maxBottom,
        fromLayout.y + nodeDims(fromMeta).height / 2
      );
    });
    return maxBottom;
  }

  function applyFlowLayout(data, g, nodeById, elementMap, childToGroup) {
    var triggersGroup = findGroupByTitle(data, 'Triggers');
    var graphCenterX = 0;

    if (triggersGroup && triggersGroup.children.length) {
      graphCenterX = triggersGroupCenterX(triggersGroup, g) || 0;
      var frameTop = groupContentTop(triggersGroup, g, nodeById, elementMap) -
        GROUP_HEADER_HEIGHT - GROUP_INNER_PAD_Y;
      layoutStackedGroup(g, triggersGroup, nodeById, elementMap, graphCenterX, frameTop);
    }

    var condGroups = findGroupsByTitle(data, 'Conditions');
    var yCursor = triggersGroup
      ? triggersGroupFrameBottom(triggersGroup, g, nodeById, elementMap) + GAP_AFTER_TRIGGERS
      : 0;
    if (condGroups.length === 1) {
      layoutStackedGroup(g, condGroups[0], nodeById, elementMap, graphCenterX, yCursor);
      yCursor += estimateGroupHeight(condGroups[0], nodeById, elementMap);
    } else if (condGroups.length) {
      yCursor = layoutConditionsGroupsRow(
        data, g, nodeById, elementMap, graphCenterX, yCursor
      );
    }

    var actionsGroup = findGroupByTitle(data, 'Actions');
    if (!actionsGroup) return;

    var maxCondBottom = maxConditionExitBottom(data, g, nodeById, childToGroup);
    if (isFinite(maxCondBottom)) {
      layoutStackedGroup(
        g, actionsGroup, nodeById, elementMap, graphCenterX, maxCondBottom + GAP_BEFORE_ACTIONS
      );
      return;
    }

    var actionsTop = groupContentTop(actionsGroup, g, nodeById, elementMap) -
      GROUP_HEADER_HEIGHT - GROUP_INNER_PAD_Y;
    layoutStackedGroup(g, actionsGroup, nodeById, elementMap, graphCenterX, actionsTop);
  }

  function updateNodeElementPositions(data, g, nodeById, elementMap, bounds) {
    data.nodes.forEach(function(node) {
      var el = elementMap[node.id];
      var layoutNode = g.node(node.id);
      if (!el || !layoutNode) return;
      var w = el.offsetWidth || nodeDims(node).width;
      var h = el.offsetHeight || nodeDims(node).height;
      el.style.left = (layoutX(layoutNode.x, bounds) - w / 2) + 'px';
      el.style.top = (layoutY(layoutNode.y, bounds) - h / 2) + 'px';
    });
  }

  function buildChildToGroupMap(groups) {
    var map = {};
    (groups || []).forEach(function(group) {
      (group.children || []).forEach(function(childId) {
        map[childId] = group.id;
      });
    });
    return map;
  }

  function drawGroupFrames(layer, data, g, elementMap, bounds) {
    var frames = {};
    (data.groups || []).forEach(function(group) {
      var childIds = group.children || [];
      if (!childIds.length) return;

      var minX = Infinity;
      var minY = Infinity;
      var maxX = -Infinity;
      var maxY = -Infinity;

      childIds.forEach(function(childId) {
        var layoutNode = g.node(childId);
        var el = elementMap[childId];
        if (!layoutNode || !el) return;
        var w = el.offsetWidth || nodeDims({ kind: 'action' }).width;
        var h = el.offsetHeight || nodeDims({ kind: 'action' }).height;
        var left = layoutNode.x - w / 2;
        var top = layoutNode.y - h / 2;
        minX = Math.min(minX, left);
        minY = Math.min(minY, top);
        maxX = Math.max(maxX, left + w);
        maxY = Math.max(maxY, top + h);
      });

      if (!isFinite(minX)) return;

      var frameLeft = minX - GROUP_PAD.left;
      var frameTop = minY - GROUP_HEADER_HEIGHT - GROUP_INNER_PAD_Y;
      var frameWidth = maxX - minX + GROUP_PAD.left + GROUP_PAD.right;
      var frameHeight = GROUP_HEADER_HEIGHT + GROUP_INNER_PAD_Y * 2 + (maxY - minY);

      var frame = document.createElement('div');
      frame.className = 'automation-flow-group-frame';
      frame.style.left = (frameLeft - bounds.offsetX) + 'px';
      frame.style.top = (frameTop - bounds.offsetY) + 'px';
      frame.style.width = frameWidth + 'px';
      frame.style.height = frameHeight + 'px';

      var header = document.createElement('div');
      header.className = 'automation-flow-group-frame__header';
      if (group.icon) {
        var icon = document.createElement('i');
        icon.className = 'fa ' + group.icon;
        header.appendChild(icon);
      }
      var title = document.createElement('span');
      title.textContent = group.title;
      header.appendChild(title);
      frame.appendChild(header);

      layer.insertBefore(frame, layer.firstChild);

      var layoutTop = frameTop - bounds.offsetY;
      frames[group.id] = {
        centerX: frameLeft - bounds.offsetX + frameWidth / 2,
        top: layoutTop,
        bottom: layoutTop + frameHeight
      };
    });
    return frames;
  }

  function isEdgeIntoGroup(edge, childToGroup) {
    var toGroup = childToGroup[edge.to];
    if (!toGroup) return false;
    return childToGroup[edge.from] !== toGroup;
  }

  function isEdgeFromTriggersToConditions(edge, data, childToGroup) {
    var triggersGroup = findGroupByTitle(data, 'Triggers');
    if (!triggersGroup || triggersGroup.children.indexOf(edge.from) < 0) {
      return false;
    }
    var toGroupId = childToGroup[edge.to];
    if (!toGroupId) return false;
    var toGroup = (data.groups || []).find(function(grp) {
      return grp.id === toGroupId;
    });
    return Boolean(toGroup && toGroup.title === 'Conditions');
  }

  function drawTriggersToConditionsEdges(svg, data, childToGroup, groupFrames, triggersGroup) {
    var triggersFrame = groupFrames[triggersGroup.id];
    if (!triggersFrame) return;

    var fromPoint = { x: triggersFrame.centerX, y: triggersFrame.bottom };
    var targets = [];

    findGroupsByTitle(data, 'Conditions').forEach(function(condGroup) {
      var linked = data.edges.some(function(edge) {
        return isEdgeFromTriggersToConditions(edge, data, childToGroup) &&
          condGroup.children.indexOf(edge.to) >= 0;
      });
      if (!linked) return;
      var frame = groupFrames[condGroup.id];
      if (!frame) return;
      targets.push({ x: frame.centerX, y: frame.top });
    });

    if (!targets.length) return;
    if (targets.length === 1) {
      appendSvgPath(svg, bezierPath(fromPoint.x, fromPoint.y, targets[0].x, targets[0].y));
      return;
    }
    appendSvgPath(
      svg,
      busFanoutPath(fromPoint, targets, MULTI_COND_STEM_FROM_TRIGGERS)
    );
  }

  function drawConditionsToActionsEdges(svg, data, childToGroup, groupFrames) {
    var actionsGroup = findGroupByTitle(data, 'Actions');
    if (!actionsGroup) return;
    var actionsFrame = groupFrames[actionsGroup.id];
    if (!actionsFrame) return;

    var targetPoint = { x: actionsFrame.centerX, y: actionsFrame.top };
    var sources = [];
    var seen = {};

    data.edges.forEach(function(edge) {
      if (!isEdgeIntoGroup(edge, childToGroup)) return;
      if (actionsGroup.children.indexOf(edge.to) < 0) return;

      var fromGroupId = childToGroup[edge.from];
      if (!fromGroupId || seen[fromGroupId]) return;
      var frame = groupFrames[fromGroupId];
      var group = (data.groups || []).find(function(grp) {
        return grp.id === fromGroupId;
      });
      if (!frame || !group || group.title !== 'Conditions') return;

      seen[fromGroupId] = true;
      sources.push({ x: frame.centerX, y: frame.bottom });
    });

    if (!sources.length) return;
    if (sources.length === 1) {
      appendSvgPath(
        svg,
        bezierPath(sources[0].x, sources[0].y, targetPoint.x, targetPoint.y)
      );
      return;
    }
    appendSvgPath(
      svg,
      busMergePathFromFrames(sources, targetPoint, MULTI_COND_BUS_STUB)
    );
  }

  function applyFitToContainer(container, viewport, stage, graphWidth, graphHeight) {
    function fit() {
      var available = container.clientWidth;
      if (!available || !graphWidth) return;

      var scale = Math.min(1, available / graphWidth);
      scale = Math.max(MIN_FIT_SCALE, scale);

      stage.style.transform = 'scale(' + scale + ')';
      stage.style.transformOrigin = 'top center';
      viewport.style.height = Math.ceil(graphHeight * scale) + 'px';
      container.style.height = (Math.ceil(graphHeight * scale) + 16) + 'px';
    }

    fit();
    requestAnimationFrame(fit);

    if (container._flowGraphResizeObserver) {
      container._flowGraphResizeObserver.disconnect();
    }
    if (typeof ResizeObserver !== 'undefined') {
      container._flowGraphResizeObserver = new ResizeObserver(fit);
      container._flowGraphResizeObserver.observe(container);
    } else {
      global.addEventListener('resize', fit);
    }
  }

  function render(container, data) {
    var nodeById = {};
    data.nodes.forEach(function(n) { nodeById[n.id] = n; });

    var childToGroup = buildChildToGroupMap(data.groups);
    var g = buildDagreGraph(data, childToGroup);
    applyFlowLayout(data, g, nodeById, null, childToGroup);

    var bounds = measureGraphBounds(data, g, nodeById);

    if (container._flowGraphResizeObserver) {
      container._flowGraphResizeObserver.disconnect();
      container._flowGraphResizeObserver = null;
    }

    container.innerHTML = '';
    container.style.width = '100%';

    var viewport = document.createElement('div');
    viewport.className = 'automation-flow-graph__viewport';

    var stage = document.createElement('div');
    stage.className = 'automation-flow-graph__stage';
    stage.style.width = bounds.width + 'px';
    stage.style.height = bounds.height + 'px';
    viewport.appendChild(stage);
    container.appendChild(viewport);

    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'automation-flow-graph__edges');
    svg.setAttribute('width', bounds.width);
    svg.setAttribute('height', bounds.height);
    stage.appendChild(svg);

    var layer = document.createElement('div');
    layer.className = 'automation-flow-graph__nodes';
    stage.appendChild(layer);

    var elementMap = {};
    data.nodes.forEach(function(node) {
      var layoutNode = g.node(node.id);
      if (!layoutNode) return;
      var el = createNodeElement(node, layoutNode, bounds);
      elementMap[node.id] = el;
      layer.appendChild(el);
    });

    applyFlowLayout(data, g, nodeById, elementMap, childToGroup);
    updateNodeElementPositions(data, g, nodeById, elementMap, bounds);
    bounds = measureGraphBounds(data, g, nodeById);
    stage.style.width = bounds.width + 'px';
    stage.style.height = bounds.height + 'px';
    svg.setAttribute('width', bounds.width);
    svg.setAttribute('height', bounds.height);
    updateNodeElementPositions(data, g, nodeById, elementMap, bounds);

    var groupFrames = drawGroupFrames(layer, data, g, elementMap, bounds);
    var triggersGroup = findGroupByTitle(data, 'Triggers');
    if (triggersGroup) {
      drawTriggersToConditionsEdges(svg, data, childToGroup, groupFrames, triggersGroup);
    }
    drawConditionsToActionsEdges(svg, data, childToGroup, groupFrames);

    applyFitToContainer(container, viewport, stage, bounds.width, bounds.height);
  }

  var AutomationFlowGraph = {
    init: function(containerSelector, dataScriptId) {
      var container = document.querySelector(containerSelector);
      if (!container || typeof dagre === 'undefined') return;
      var data = readGraphData(dataScriptId);
      if (!data) return;
      render(container, data);
    }
  };

  global.AutomationFlowGraph = AutomationFlowGraph;
})(typeof window !== 'undefined' ? window : this);
