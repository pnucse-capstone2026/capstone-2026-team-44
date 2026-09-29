from pyvis.network import Network
import sqlite3
import os
import json
from urllib.parse import urlparse

#parents마다 색깔 지정
def get_parent_color(idx):
    palette = [
        "#3498db", "#f39c12", "#2ecc71", "#9b59b6", "#e6194b",
        "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4",
        "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080"
    ]
    return palette[idx % len(palette)]

def generate_interactive_graph(db_path, url, output_html=None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t1.link, t1.parent, t1.depth, t1.input_fields
        FROM crawl_links t1
        INNER JOIN (
            SELECT link, MIN(collected_time) AS min_time
            FROM crawl_links
            GROUP BY link
        ) t2
        ON t1.link = t2.link AND t1.collected_time = t2.min_time
    """)
    rows = cursor.fetchall()
    conn.close()

    print(f"불러온 링크 수: {len(rows)}")

    net = Network(height="1200px", width="100%", bgcolor="#ffffff", font_color="black", directed=True)
    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {
            "gravitationalConstant": -80,
            "centralGravity": 0.01,
            "springLength": 100,
            "springConstant": 0.09,
            "avoidOverlap": 1
        }
      },
      "nodes": {
        "scaling": { "min": 5, "max": 25 },
        "font": { "size": 12, "face": "arial" },
        "borderWidth": 1,
        "shadow": true
      },
      "edges": {
        "arrows": { "to": { "enabled": true }},
        "smooth": { "enabled": true }
      },
      "interaction": {
        "hover": true,
        "zoomView": true,
        "dragView": true,
        "dragNodes": true
      }
    }
    """)

    added_nodes = set()
    parent_colors = {}
    parent_idx = 0
    nodes_with_info = []

    for link, parent, depth, input_fields_json in rows:
        try:
            input_fields = json.loads(input_fields_json)
        except:
            input_fields = []

        has_input = bool(input_fields)

        if depth == 0 or not parent:
            color = "#d62728"  # 루트는 빨간색
        elif not has_input:
            color = "#bdc3c7"  # 입력필드 없으면 회색
        else:
            if parent not in parent_colors:
                parent_colors[parent] = get_parent_color(parent_idx)
                parent_idx += 1
            color = parent_colors[parent]

        size = 22 if depth == 0 else max(16 - depth * 2, 6)
        shape = "star" if depth == 0 else "dot"
        display_label = link if len(link) <= 40 else link[:37] + "..."

        # 전체 정보를 담을 info(HTML용)
        info_html = f"""
        <b>Link:</b> {link}<br>
        <b>Depth:</b> {depth}<br>
        <b>Parent:</b> {parent}<br>
        <b>Input Fields:</b><br>
        <pre style='white-space:pre-wrap;font-size:13px'>{json.dumps(input_fields, indent=2, ensure_ascii=False)}</pre>
        """

        if link not in added_nodes:
            net.add_node(link, label=display_label, color=color, shape=shape, size=size)
            added_nodes.add(link)
            nodes_with_info.append({'id': link, 'info_html': info_html})

        if parent and parent not in added_nodes:
            net.add_node(parent, label=" ", color="#bdc3c7", size=10)
            added_nodes.add(parent)

        if parent:
            net.add_edge(parent, link)

    if output_html is None:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace(":", "_").replace(".", "_")
        output_html = os.path.join("data", f"{domain}_graph.html")

    net.write_html(output_html)
    print(f"시각화 완료: {output_html}")

    inject_info_panel(output_html, nodes_with_info, parent_colors)

def inject_info_panel(html_path, nodes_with_info, parent_colors):
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 📦 동적 범례 HTML 구성
    legend_entries = """
    <div style="margin-bottom:4px;">
      <span style="display:inline-block;width:16px;height:16px;background:#d62728;margin-right:6px;"></span>루트 노드 (Depth 0)
    </div>
    <div style="margin-bottom:4px;">
      <span style="display:inline-block;width:16px;height:16px;background:#bdc3c7;margin-right:6px;"></span>입력 필드 없음
    </div>
    """

    # 부모 그룹 색상 추가
    for parent, color in parent_colors.items():
        short = parent if len(parent) < 40 else parent[:35] + "..."
        entry = f"""
        <div style="margin-bottom:4px;">
          <span style="display:inline-block;width:16px;height:16px;background:{color};margin-right:6px;"></span>{short}
        </div>
        """
        legend_entries += entry

    legend_div = f"""
    <div id="legend-box" style="position:fixed; top:40px; left:40px; width:300px; max-height:500px; overflow:auto;
     background:#fff; border:1px solid #ccc; padding:10px; font-size:14px; z-index:1000; box-shadow:2px 2px 6px rgba(0,0,0,0.1);">
      {legend_entries}
    </div>
    """
    html = html.replace('<body>', f'<body>\n{legend_div}', 1)

    # 기존 info panel 삽입
    info_div = """
    <div id="info-panel" style="position:fixed; top:40px; right:40px; width:420px; height:460px; border:1px solid #aaa; background:#fcfcfc; overflow:auto; z-index:1000; padding:14px; font-family:monospace; font-size:15px; display:none;"></div>
    """
    html = html.replace('<body>', f'<body>\n{info_div}', 1)

    # node info + JS 삽입
    node_infos = {node['id']: node['info_html'] for node in nodes_with_info}
    info_js = "var nodeInfos = " + json.dumps(node_infos, ensure_ascii=False) + ";\n"

    js_code = f"""
    <script>
    {info_js}
    network.on("click", function(params) {{
      if (params.nodes.length === 1) {{
        var nodeId = params.nodes[0];
        var infoDiv = document.getElementById("info-panel");
        infoDiv.innerHTML = nodeInfos[nodeId] || "<i>정보 없음</i>";
        infoDiv.style.display = "block";
      }}
    }});
    network.on("deselectNode", function(params) {{
      var infoDiv = document.getElementById("info-panel");
      infoDiv.style.display = "none";
    }});
    </script>
    """
    html = html.replace("</body>", js_code + "\n</body>")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    html = html.replace("</body>", js_code + "\n</body>")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
