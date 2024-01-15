import networkx as nx
import matplotlib.pyplot as plt
import json, time, os

class CentralServer:
    def __init__(self, label, ip_address):
        self.label = label
        self.ip_address = ip_address

class OTFieldMapper:
    def __init__(self):
        self.graph = nx.Graph()
        self.data = {"nodes": [], "lines": []}

    def add_node(self, node_type, label, ip_address, x, y):
        node_id = f"{node_type}_{label}"
        self.graph.add_node(node_id, type=node_type, label=label, ip_address=ip_address, pos=(x, y))
        self.data["nodes"].append({"id": node_id, "type": node_type, "label": label, "ip_address": ip_address, "pos": (x, y)})

    def add_communication_line(self, line_id, protocol, color, x, y):
        self.graph.add_node(line_id, type="CommunicationLine", protocol=protocol, color=color, pos=(x, y))
        self.data["lines"].append({"id": line_id,"type":"CommunicationLine" , "protocol": protocol, "color": color, "pos": (x, y)})

    def link_node_to_line(self, node_id, line_id, color):
        if node_id in self.graph.nodes and line_id in self.graph.nodes:
            self.graph.add_edge(node_id, line_id, color=color)
        else:
            print("Node or line not found.")

    def link_server_to_line(self, server, line_id, color):
        server_id = f"CentralServer_{server.label}"
        self.graph.add_node(server_id, type="CentralServer", label=server.label, ip_address=server.ip_address, color=color, pos=(0, 0))
        self.graph.add_edge(server_id, line_id, color=color)
        self.data["nodes"].append({"id": server_id, "type": "CentralServer", "label": server.label, "ip_address": server.ip_address, "color": color, "pos": (0, 0)})

    def display_graph(self):
        # Adjust the figure size to 13:9 width:height ratio
        plt.figure(figsize=(13, 9))
        
        # Calculate positions for non-CommunicationLine nodes
        non_communicationline_nodes = [node for node, data in self.graph.nodes(data=True) if data['type'] != 'CommunicationLine']
        n = len(non_communicationline_nodes)
        top_row_positions = {node: (i * 13 / (n // 2), 7) for i, node in enumerate(non_communicationline_nodes[:n//2])}
        bottom_row_positions = {node: (i * 13 / (n // 2), 0) for i, node in enumerate(non_communicationline_nodes[n//2:])}
        
        # Calculate positions for CommunicationLine nodes
        communicationline_nodes = [node for node, data in self.graph.nodes(data=True) if data['type'] == 'CommunicationLine']
        communicationline_positions = {node: (i * 13 / len(communicationline_nodes), 3.5) for i, node in enumerate(communicationline_nodes)}
        
        # Combine positions for all nodes
        pos = {**top_row_positions, **bottom_row_positions, **communicationline_positions}
        
        node_colors = [data['color'] if 'color' in data else 'blue' for node, data in self.graph.nodes(data=True) if data['type'] != 'CommunicationLine']
        line_colors = [data['color'] for node, data in self.graph.nodes(data=True) if data['type'] == 'CommunicationLine']

        # Draw non-CommunicationLine nodes at the top and bottom
        nx.draw_networkx_nodes(self.graph, pos, nodelist=non_communicationline_nodes[:n//2], node_color=node_colors[:n//2])
        nx.draw_networkx_nodes(self.graph, pos, nodelist=non_communicationline_nodes[n//2:], node_color=node_colors[n//2:])

        # Draw CommunicationLine nodes in the middle
        nx.draw_networkx_nodes(self.graph, pos, nodelist=communicationline_nodes, node_color='white', edgecolors=line_colors, node_size=500)

        # Draw CommunicationLine edges
        for node, data in self.graph.nodes(data=True):
            if data['type'] == 'CommunicationLine':
                edge_color = data['color']
                edges = self.graph.edges(node)
                for edge in edges:
                    nx.draw_networkx_edges(self.graph, pos, edgelist=[edge], edge_color=edge_color)

        nx.draw_networkx_labels(self.graph, pos)
        plt.axis('off')  # Turn off axis

        # Include both nodes and edges in the data dictionary
        self.data["edges"] = []
        for edge in self.graph.edges(data=True):
            source, target, data = edge
            edge_data = {"source": source, "target": target}
            edge_data.update(data)
            self.data["edges"].append(edge_data)
        current_time = int(time.time())
        file_name = f"OT_Field_{time.strftime('%m_%d_%Y')}_{current_time}.json"
        with open(file_name, 'w') as json_file:
            json.dump(self.data, json_file, indent=4)

        plt.show()

    @classmethod
    def import_and_display_graph(cls, json_file):
        with open(json_file, 'r') as json_file:
            data = json.load(json_file)

        mapper = cls()
        mapper.data = data
        mapper.graph = nx.Graph()

        for node_data in data["nodes"]:
            mapper.graph.add_node(node_data["id"], **node_data)

        for line_data in data["lines"]:
            mapper.graph.add_node(line_data["id"], **line_data)

        for edge_data in data.get("edges", []):
            source = edge_data["source"]
            target = edge_data["target"]
            color = edge_data["color"]
            mapper.graph.add_edge(source, target, color=color)

        mapper.display_graph()

class EVFieldMapper:
    def __init__(self):
        self.graph = nx.Graph()
        self.data = {"nodes": [], "lines": []}

    def add_gs(self, gs_label, cs_count):
        gs_id = f"GS_{gs_label}"
        self.graph.add_node(gs_id, type="GS", label=gs_label, cs_count=cs_count)
        self.data["nodes"].append({"id": gs_id, "type": "GS", "label": gs_label, "cs_count": cs_count})

    def add_cs(self, gs_label, cs_label):
        gs_id = f"GS_{gs_label}"
        cs_id = f"CS_{cs_label}"
        self.graph.add_node(cs_id, type="CS", label=cs_label)
        self.graph.add_edge(gs_id, cs_id)
        self.data["nodes"].append({"id": cs_id, "type": "CS", "label": cs_label})

    def link_gs_to_server(self, gs_label, server):
        gs_id = f"GS_{gs_label}"
        server_id = f"CentralServer_{server.label}"
        self.graph.add_node(server_id, type="CentralServer", label=server.label, ip_address=server.ip_address)
        self.graph.add_edge(gs_id, server_id)
        self.data["nodes"].append({"id": server_id, "type": "CentralServer", "label": server.label, "ip_address": server.ip_address})

    def display_graph(self):
        nx.draw(self.graph, with_labels=True, font_weight='bold')

        # Include both nodes and edges in the data dictionary
        self.data["edges"] = []
        for edge in self.graph.edges(data=True):
            source, target, data = edge
            edge_data = {"source": source, "target": target}
            edge_data.update(data)
            self.data["edges"].append(edge_data)
        current_time = int(time.time())
        file_name = f"EV_Field_{time.strftime('%m_%d_%Y')}_{current_time}.json"
        with open(file_name, 'w') as json_file:
            json.dump(self.data, json_file, indent=4)

        plt.show()

    @classmethod
    def import_and_display_graph(cls, json_file):
        with open(json_file, 'r') as json_file:
            data = json.load(json_file)

        mapper = cls()
        mapper.data = data
        mapper.graph = nx.Graph()

        for node_data in data["nodes"]:
            mapper.graph.add_node(node_data["id"], **node_data)

        for line_data in data["lines"]:
            mapper.graph.add_node(line_data["id"], **line_data)

        for edge_data in data["edges"]:
            mapper.graph.add_edge(edge_data["source"], edge_data["target"], **edge_data)

        mapper.display_graph()

# Test script
def main(display=True):
        # OT Field Mapping
    ot_mapper = OTFieldMapper()

    ot_mapper.add_node("Secure IED", "IED1A", "185.175.0.4", x=1, y=0)
    ot_mapper.add_node("Secure IED", "IED4C", "185.175.0.8", x=2, y=0)
    ot_mapper.add_node("Secure SCADA HMI", "SCADA_HMI", "185.175.0.2", x=3, y=0)
    ot_mapper.add_node("Central Agent", "CA", "185.175.0.6", x=0, y=1)
    ot_mapper.add_node("Misc.", "ELK_Stack", "0.0.0.0", x=2, y=2)

    ot_mapper.add_communication_line("MODBUS_Line", "MODBUS", "red", x=1, y=1)
    ot_mapper.add_communication_line("ACL_Line", "ACL", "green", x=2, y=1)
    ot_mapper.add_communication_line("ELK_Line", "ELK", "blue", x=3, y=1)

    ot_mapper.link_node_to_line("Secure IED_IED1A", "MODBUS_Line", "red")
    ot_mapper.link_node_to_line("Secure IED_IED1A", "ACL_Line", "green")
    ot_mapper.link_node_to_line("Secure IED_IED1A", "ELK_Line", "blue")

    ot_mapper.link_node_to_line("Secure IED_IED4C", "MODBUS_Line", "red")
    ot_mapper.link_node_to_line("Secure IED_IED4C", "ACL_Line", "green")
    ot_mapper.link_node_to_line("Secure IED_IED4C", "ELK_Line", "blue")

    ot_mapper.link_node_to_line("Secure SCADA HMI_SCADA_HMI", "MODBUS_Line", "red")
    ot_mapper.link_node_to_line("Secure SCADA HMI_SCADA_HMI", "ELK_Line", "blue")

    ot_mapper.link_node_to_line("Central Agent_CA", "ACL_Line", "green")
    ot_mapper.link_node_to_line("Central Agent_CA", "ELK_Line", "blue")

    ot_mapper.link_node_to_line("Misc._ELK_Stack", "ELK_Line", "blue")

    if display:    ot_mapper.display_graph()

    # EV Field Mapping
    ev_mapper = EVFieldMapper()

    # Create Central Server
    ev_server = CentralServer("TCP_Server", "185.175.0.10")


    ev_mapper.add_gs("GS1", cs_count=2)
    ev_mapper.add_gs("GS2", cs_count=3)
    ev_mapper.add_gs("GS3", cs_count=1)

    ev_mapper.add_cs("GS1", "CS1")
    ev_mapper.add_cs("GS1", "CS2")

    ev_mapper.add_cs("GS2", "CS3")
    ev_mapper.add_cs("GS2", "CS4")
    ev_mapper.add_cs("GS2", "CS5")

    ev_mapper.add_cs("GS3", "CS6")

    ev_mapper.link_gs_to_server("GS1", ev_server)
    ev_mapper.link_gs_to_server("GS2", ev_server)
    ev_mapper.link_gs_to_server("GS3", ev_server)

    if display:    ev_mapper.display_graph()

def importTest():
    for file in os.listdir():
        if file.startswith("OT"):
            ot_json_file = file
        if file.startswith("EV"):
            ev_json_file = file
    OTFieldMapper.import_and_display_graph(ot_json_file)
    EVFieldMapper.import_and_display_graph(ev_json_file)

if __name__ == "__main__":
    main(display=False)
    # importTest()