# import networkx as nx
# import pandas as pd
# import numpy as np
# from collections import defaultdict
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
# import matplotlib.pyplot as plt
#
#
# class DynamicGraphAnomalyDetector:
#     def __init__(self, time_window=5, attack_threshold=0.5, min_occurrences=3):
#         self.time_window = time_window
#         self.attack_threshold = attack_threshold
#         self.min_occurrences = min_occurrences
#         self.graphs = []
#         self.edge_features = defaultdict(lambda: defaultdict(list))
#         self.anomalies = None
#
#     def build_graph(self, df, timestamp):
#         G = nx.Graph()
#         attack_edges = 0
#         benign_edges = 0
#         for _, row in df.iterrows():
#             user = f"U_{row['userId']}"
#             app = f"A_{row['appId']}"
#             resource = f"R_{row['resourceId']}"
#
#             G.add_node(user, type='User')
#             G.add_node(app, type='App')
#             G.add_node(resource, type='Resource')
#
#             is_attack = int(row['is_attack'])
#             # Add edges and count attack and benign edges correctly
#             G.add_edge(user, app, weight=1, is_attack=is_attack)
#             G.add_edge(app, resource, weight=1, is_attack=is_attack)
#             if is_attack:
#                 attack_edges += 2
#             else:
#                 benign_edges += 2
#
#         self.graphs.append((timestamp, G))
#         print(f"Graph built for timestamp {timestamp} with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
#         print(f"Attack edges: {attack_edges}, Benign edges: {benign_edges}")
#         return G
#
#     def extract_features(self, G, timestamp):
#         for u, v, data in G.edges(data=True):
#             edge = (u, v) if u < v else (v, u)
#             self.edge_features[edge]['weight'].append(data['weight'])
#             self.edge_features[edge]['is_attack'].append(data['is_attack'])
#             self.edge_features[edge]['timestamp'].append(timestamp)
#
#     def detect_anomalies(self):
#         anomalies = set()
#         for edge, features in self.edge_features.items():
#             if len(features['weight']) >= self.min_occurrences:
#                 attack_ratio = sum(features['is_attack']) / len(features['weight'])
#                 if attack_ratio > self.attack_threshold:
#                     anomalies.add(edge)
#
#         self.anomalies = anomalies
#         return self.anomalies
#
#     def evaluate_results(self):
#         G = self.graphs[-1][1]  # Get the most recent graph
#         true_labels = []
#         pred_labels = []
#
#         for u, v, data in G.edges(data=True):
#             true_labels.append(data['is_attack'])
#             pred_labels.append(1 if (u, v) in self.anomalies or (v, u) in self.anomalies else 0)
#
#         accuracy = accuracy_score(true_labels, pred_labels)
#         precision = precision_score(true_labels, pred_labels, zero_division=0)
#         recall = recall_score(true_labels, pred_labels, zero_division=0)
#         f1 = f1_score(true_labels, pred_labels, zero_division=0)
#
#         print("\nEvaluation Results:")
#         print(f"Accuracy: {accuracy:.4f}")
#         print(f"Precision: {precision:.4f}")
#         print(f"Recall: {recall:.4f}")
#         print(f"F1-score: {f1:.4f}")
#
#         return accuracy, precision, recall, f1
#
#     def visualize_anomalies(self):
#         G = self.graphs[-1][1]  # Get the most recent graph
#         pos = nx.spring_layout(G)
#
#         plt.figure(figsize=(12, 8))
#         nx.draw(G, pos, node_color='lightblue', with_labels=True, node_size=500, font_size=8)
#
#         nx.draw_networkx_edges(G, pos, edgelist=self.anomalies, edge_color='red', width=2)
#
#         plt.title("Dynamic Graph with Detected Anomalies (in red)")
#         plt.show()
#
#
# def load_and_preprocess_data(file_path, attack_sample_ratio=0.2):
#     df = pd.read_csv(file_path)
#     df['createdDateTime'] = pd.to_datetime(df['createdDateTime'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
#
#     # Separate benign and attack instances
#     benign_df = df[df['is_attack'] == 0]
#     attack_df = df[df['is_attack'] == 1]
#
#     # Sample 20% of attack instances
#     attack_sample = attack_df.sample(frac=attack_sample_ratio, random_state=42)
#
#     # Combine all benign instances with the sampled attack instances
#     sampled_df = pd.concat([benign_df, attack_sample], ignore_index=True)
#
#     print(f"Sampled data shape: {sampled_df.shape}")
#     print(f"Sampled benign instances: {len(benign_df)}")
#     print(f"Sampled attack instances: {len(attack_sample)}")
#
#     return sampled_df
#
#
# if __name__ == "__main__":
#     df = load_and_preprocess_data('benign_exploration_attacks.csv', attack_sample_ratio=0.2)
#
#     detector = DynamicGraphAnomalyDetector(time_window=5, attack_threshold=0.5, min_occurrences=3)
#
#     # Create time steps based on actual data range
#     actual_start = df['createdDateTime'].min()
#     actual_end = df['createdDateTime'].max()
#     time_steps = pd.date_range(start=actual_start, end=actual_end, periods=10)
#
#     for timestamp in time_steps:
#         snapshot = df[df['createdDateTime'] <= timestamp]
#         G = detector.build_graph(snapshot, timestamp)
#         detector.extract_features(G, timestamp)
#
#     anomalies = detector.detect_anomalies()
#
#     print(f"\nDetected {len(anomalies)} anomalous edges")
#     for edge in list(anomalies)[:10]:  # Print first 10 anomalies
#         print(f"Anomalous edge: {edge}")
#
#     accuracy, precision, recall, f1 = detector.evaluate_results()
#
#     detector.visualize_anomalies()
#
#     # Additional analysis
#     G = detector.graphs[-1][1]  # Get the most recent graph
#     attack_edges = sum(1 for _, _, data in G.edges(data=True) if data['is_attack'] == 1)
#     benign_edges = G.number_of_edges() - attack_edges
#     print(f"\nTotal edges: {G.number_of_edges()}")
#     print(f"Attack edges: {attack_edges}")
#     print(f"Benign edges: {benign_edges}")
#     print(f"Percentage of attack edges: {attack_edges / G.number_of_edges() * 100:.2f}%")
#
#     anomaly_edges = len(anomalies)
#     print(f"Edges flagged as anomalous: {anomaly_edges}")
#     print(f"Percentage of edges flagged as anomalous: {anomaly_edges / G.number_of_edges() * 100:.2f}%")

import networkx as nx
import pandas as pd
import numpy as np
from collections import defaultdict
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt


class DynamicGraphAnomalyDetector:
    def __init__(self, time_window=5, attack_threshold=0.8, min_occurrences=3):
        self.time_window = time_window
        self.attack_threshold = attack_threshold
        self.min_occurrences = min_occurrences
        self.graphs = []
        self.edge_features = defaultdict(lambda: defaultdict(list))
        self.anomalies = None

    def build_graph(self, df, timestamp):
        G = nx.Graph()
        attack_edges = 0
        benign_edges = 0
        for _, row in df.iterrows():
            user = f"U_{row['userId']}"
            app = f"A_{row['appId']}"
            resource = f"R_{row['resourceId']}"

            G.add_node(user, type='User')
            G.add_node(app, type='App')
            G.add_node(resource, type='Resource')

            is_attack = int(row['is_attack'])
            G.add_edge(user, app, weight=1, is_attack=is_attack)
            G.add_edge(app, resource, weight=1, is_attack=is_attack)
            if is_attack:
                attack_edges += 2
            else:
                benign_edges += 2

        self.graphs.append((timestamp, G))
        print(f"Graph built for timestamp {timestamp} with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
        print(f"Attack edges: {attack_edges}, Benign edges: {benign_edges}")
        print(f"Unique 'is_attack' values in graph: {set(nx.get_edge_attributes(G, 'is_attack').values())}")
        return G

    def extract_features(self, G, timestamp):
        for u, v, data in G.edges(data=True):
            edge = (u, v) if u < v else (v, u)
            self.edge_features[edge]['weight'].append(data['weight'])
            self.edge_features[edge]['is_attack'].append(data['is_attack'])
            self.edge_features[edge]['timestamp'].append(timestamp)

    def detect_anomalies(self):
        anomalies = set()
        for edge, features in self.edge_features.items():
            if len(features['weight']) >= self.min_occurrences:
                attack_ratio = sum(features['is_attack']) / len(features['weight'])
                if attack_ratio > self.attack_threshold:
                    anomalies.add(edge)

        self.anomalies = anomalies
        return self.anomalies

    def evaluate_results(self):
        G = self.graphs[-1][1]  # Get the most recent graph
        true_labels = []
        pred_labels = []

        for u, v, data in G.edges(data=True):
            true_labels.append(data['is_attack'])
            pred_labels.append(1 if (u, v) in self.anomalies or (v, u) in self.anomalies else 0)

        accuracy = accuracy_score(true_labels, pred_labels)
        precision = precision_score(true_labels, pred_labels, zero_division=0)
        recall = recall_score(true_labels, pred_labels, zero_division=0)
        f1 = f1_score(true_labels, pred_labels, zero_division=0)

        print("\nEvaluation Results:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-score: {f1:.4f}")

        return accuracy, precision, recall, f1

    def visualize_anomalies(self):
        G = self.graphs[-1][1]  # Get the most recent graph
        pos = nx.spring_layout(G)

        plt.figure(figsize=(12, 8))
        nx.draw(G, pos, node_color='lightblue', with_labels=True, node_size=500, font_size=8)

        nx.draw_networkx_edges(G, pos, edgelist=self.anomalies, edge_color='red', width=2)

        plt.title("Dynamic Graph with Detected Anomalies (in red)")
        plt.show()


import pandas as pd
from datetime import datetime


def load_and_preprocess_data(file_path, attack_sample_ratio=0.2):
    df = pd.read_csv(file_path)

    # Convert all datetime strings to datetime objects using a more flexible approach
    df['createdDateTime'] = pd.to_datetime(df['createdDateTime'], format='mixed', utc=True)

    # Separate benign and attack instances
    benign_df = df[df['is_attack'] == 0]
    attack_df = df[df['is_attack'] == 1]

    # Sample attack instances
    attack_sample = attack_df.sample(frac=attack_sample_ratio, random_state=42)

    # Combine all benign instances with the sampled attack instances
    sampled_df = pd.concat([benign_df, attack_sample], ignore_index=True)

    # Sort the dataframe by timestamp to ensure chronological order
    sampled_df = sampled_df.sort_values('createdDateTime')

    print(f"Sampled data shape: {sampled_df.shape}")
    print(f"Sampled benign instances: {len(benign_df)}")
    print(f"Sampled attack instances: {len(attack_sample)}")
    print(f"Unique 'is_attack' values in sampled data: {sampled_df['is_attack'].unique()}")
    print(f"Date range: {sampled_df['createdDateTime'].min()} to {sampled_df['createdDateTime'].max()}")

    return sampled_df

if __name__ == "__main__":
    df = load_and_preprocess_data('./benign_exploration_attacks.csv', attack_sample_ratio=0.9)

    detector = DynamicGraphAnomalyDetector(time_window=5, attack_threshold=0.8, min_occurrences=3)

    # Create time steps based on actual data range
    actual_start = df['createdDateTime'].min()
    actual_end = df['createdDateTime'].max()
    time_steps = pd.date_range(start=actual_start, end=actual_end, periods=10)

    for timestamp in time_steps:
        snapshot = df[df['createdDateTime'] <= timestamp]
        print(f"\nSnapshot at {timestamp}:")
        print(f"Total rows: {len(snapshot)}")
        print(f"Benign instances: {sum(snapshot['is_attack'] == 0)}")
        print(f"Attack instances: {sum(snapshot['is_attack'] == 1)}")
        G = detector.build_graph(snapshot, timestamp)
        detector.extract_features(G, timestamp)

    anomalies = detector.detect_anomalies()

    print(f"\nDetected {len(anomalies)} anomalous edges")
    for edge in list(anomalies)[:10]:  # Print first 10 anomalies
        print(f"Anomalous edge: {edge}")

    accuracy, precision, recall, f1 = detector.evaluate_results()

    detector.visualize_anomalies()

    # Additional analysis
    G = detector.graphs[-1][1]  # Get the most recent graph
    attack_edges = sum(1 for _, _, data in G.edges(data=True) if data['is_attack'] == 1)
    benign_edges = G.number_of_edges() - attack_edges
    print(f"\nTotal edges: {G.number_of_edges()}")
    print(f"Attack edges: {attack_edges}")
    print(f"Benign edges: {benign_edges}")
    print(f"Percentage of attack edges: {attack_edges / G.number_of_edges() * 100:.2f}%")

    anomaly_edges = len(anomalies)
    print(f"Edges flagged as anomalous: {anomaly_edges}")
    print(f"Percentage of edges flagged as anomalous: {anomaly_edges / G.number_of_edges() * 100:.2f}%")