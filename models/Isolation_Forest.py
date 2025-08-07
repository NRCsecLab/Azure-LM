# import pandas as pd
# import networkx as nx
# import numpy as np
# from sklearn.ensemble import IsolationForest
# from sklearn.preprocessing import StandardScaler
# from sklearn.pipeline import Pipeline
# from sklearn.impute import SimpleImputer
# from sklearn.metrics import confusion_matrix
# import matplotlib.pyplot as plt
# import seaborn as sns
# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
#
#
# def print_evaluation_report(y_true, y_pred):
#     accuracy = accuracy_score(y_true, y_pred)
#     precision = precision_score(y_true, y_pred)
#     recall = recall_score(y_true, y_pred)
#     f1 = f1_score(y_true, y_pred)
#
#     print("\nEvaluation Report:")
#     print(f"Accuracy: {accuracy:.4f}")
#     print(f"Precision: {precision:.4f}")
#     print(f"Recall: {recall:.4f}")
#     print(f"F1-score: {f1:.4f}")
#
#     # Calculate additional metrics
#     tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
#     total = tn + fp + fn + tp
#
#     print(f"\nTrue Negatives: {tn} ({tn / total:.2%})")
#     print(f"False Positives: {fp} ({fp / total:.2%})")
#     print(f"False Negatives: {fn} ({fn / total:.2%})")
#     print(f"True Positives: {tp} ({tp / total:.2%})")
#
#     benign_false_positive_rate = fp / (fp + tn)
#     attack_detection_rate = tp / (tp + fn)
#
#     print(f"\nBenign data false positive rate: {benign_false_positive_rate:.2%}")
#     print(f"Attack detection rate: {attack_detection_rate:.2%}")
#
# def load_and_preprocess_data(file_path):
#     df = pd.read_csv(file_path)
#     df['createdDateTime'] = pd.to_datetime(df['createdDateTime'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
#     print(f"Total instances: {len(df)}")
#     return df
#
#
# def build_graph(df):
#     G = nx.DiGraph()
#     for _, row in df.iterrows():
#         # Add user -> app edge
#         G.add_edge(row['userId'], row['appId'],
#                    time=row['createdDateTime'],
#                    is_attack=row['is_attack'])
#
#         # Add app -> resource edge
#         G.add_edge(row['appId'], row['resourceId'],
#                    time=row['createdDateTime'],
#                    protocol=row['PROTOCOL'],
#                    is_attack=row['is_attack'])
#     return G
#
#
# def extract_edge_features(G):
#     features = []
#     labels = []
#     for edge in G.edges(data=True):
#         source, target, data = edge
#
#         # Common features for both edge types
#         edge_features = [
#             data['time'].hour if pd.notna(data['time']) else -1,
#             data['time'].weekday() if pd.notna(data['time']) else -1,
#             G.out_degree(source),
#             G.in_degree(target),
#             nx.clustering(G.to_undirected(), source),
#             nx.clustering(G.to_undirected(), target),
#             nx.degree_centrality(G)[source],
#             nx.degree_centrality(G)[target],
#             len(G.edges(source, target))  # Number of parallel edges
#         ]
#
#         # Add specific features based on edge type
#         if 'protocol' in data:  # This is an app -> resource edge
#             edge_features.extend([
#                 len(list(nx.all_simple_paths(G, source, target, cutoff=2))),
#                 hash(data['protocol']) % 10  # Simple hash of protocol
#             ])
#         else:  # This is a user -> app edge
#             edge_features.extend([
#                 len(G.out_edges(source)),  # Number of apps accessed by user
#                 len(G.in_edges(target))  # Number of users accessing the app
#             ])
#
#         features.append(edge_features)
#         labels.append(int(data['is_attack']))
#
#     feature_names = ['hour', 'weekday', 'out_degree', 'in_degree',
#                      'source_clustering', 'target_clustering', 'source_centrality',
#                      'target_centrality', 'parallel_edges', 'specific_feature_1', 'specific_feature_2']
#     return np.array(features), np.array(labels), feature_names
#
#
# class GraphAnomalyDetector:
#     def __init__(self, contamination=0.1):
#         self.model = Pipeline([
#             ('imputer', SimpleImputer(strategy='mean')),  # Impute missing values
#             ('scaler', StandardScaler()),
#             ('classifier', IsolationForest(contamination=contamination, random_state=42))
#         ])
#
#     def fit(self, features):
#         self.model.fit(features)
#
#     def predict(self, features):
#         return self.model.predict(features)
#
#
# def plot_confusion_matrix(conf_matrix):
#     plt.figure(figsize=(8, 6))
#     sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
#     plt.title('Confusion Matrix')
#     plt.ylabel('True Label')
#     plt.xlabel('Predicted Label')
#     plt.show()
#
#
# if __name__ == "__main__":
#     df = load_and_preprocess_data('benign_spread_attacks.csv')
#     G = build_graph(df)
#     features, labels, feature_names = extract_edge_features(G)
#
#     # Split data into benign and attack
#     benign_features = features[labels == 0]
#     attack_features = features[labels == 1]
#
#     # Train on benign data only
#     detector = GraphAnomalyDetector(contamination=0.1)
#     detector.fit(benign_features)
#
#     # Predict on all data
#     y_pred = detector.predict(features)
#     y_pred_binary = np.where(y_pred == -1, 1, 0)
#
#     print_evaluation_report(labels, y_pred_binary)
#
#     # Evaluate
#     conf_matrix = confusion_matrix(labels, y_pred_binary)
#     tn, fp, fn, tp = conf_matrix.ravel()
#
#     benign_false_positive_rate = fp / (fp + tn)
#     attack_detection_rate = tp / (tp + fn)
#
#     print("\nConfusion Matrix:")
#     print(conf_matrix)
#     print(f"\nBenign data false positive rate: {benign_false_positive_rate:.2%}")
#     print(f"Attack detection rate: {attack_detection_rate:.2%}")
#
#     print(f"\nData distribution:")
#     print(f"Benign instances: {sum(labels == 0)}")
#     print(f"Attack instances: {sum(labels == 1)}")
#     print(f"Total instances: {len(labels)}")
#
#     plot_confusion_matrix(conf_matrix)


import pandas as pd
import networkx as nx
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns


def load_and_preprocess_data(file_path):
    df = pd.read_csv(file_path)
    df['createdDateTime'] = pd.to_datetime(df['createdDateTime'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
    print(f"Initial data shape: {df.shape}")
    print(f"Initial benign instances: {sum(df['is_attack'] == 0)}")
    print(f"Initial attack instances: {sum(df['is_attack'] == 1)}")
    return df


def build_graphs(df):
    G_benign = nx.DiGraph()
    G_attack = nx.DiGraph()

    for _, row in df.iterrows():
        edge_data = {
            'time': row['createdDateTime'],
            'protocol': row['PROTOCOL']
        }

        if row['is_attack'] == 0:
            G_benign.add_edge(row['userId'], row['appId'], **edge_data)
            G_benign.add_edge(row['appId'], row['resourceId'], **edge_data)
        else:
            G_attack.add_edge(row['userId'], row['appId'], **edge_data)
            G_attack.add_edge(row['appId'], row['resourceId'], **edge_data)

    print(f"Benign Graph: {G_benign.number_of_edges()} edges")
    print(f"Attack Graph: {G_attack.number_of_edges()} edges")

    return G_benign, G_attack


def extract_edge_features(G):
    features = []
    for edge in G.edges(data=True):
        source, target, data = edge

        # Handle potential missing time data
        if 'time' in data and pd.notna(data['time']):
            hour = data['time'].hour
            weekday = data['time'].weekday()
        else:
            hour = -1  # Use -1 as a placeholder for missing time data
            weekday = -1

        edge_features = [
            hour,
            weekday,
            G.out_degree(source),
            G.in_degree(target),
            nx.clustering(G, source),
            nx.clustering(G, target),
            nx.degree_centrality(G)[source],
            nx.degree_centrality(G)[target],
            len(G.edges(source, target)),  # Number of parallel edges
            len(list(nx.all_simple_paths(G, source, target, cutoff=2))),
            hash(data.get('protocol', 'unknown')) % 10  # Simple hash of protocol, with default value
        ]

        features.append(edge_features)

    return np.array(features)


class GraphAnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = Pipeline([
            ('imputer', SimpleImputer(strategy='mean')),
            ('scaler', StandardScaler()),
            ('classifier', IsolationForest(contamination=contamination, random_state=42))
        ])

    def fit(self, features):
        self.model.fit(features)

    def predict(self, features):
        return self.model.predict(features)


def plot_confusion_matrix(conf_matrix):
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.show()


def print_evaluation_report(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)

    print("\nEvaluation Report:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    total = tn + fp + fn + tp

    print(f"\nTrue Negatives: {tn} ({tn / total:.2%})")
    print(f"False Positives: {fp} ({fp / total:.2%})")
    print(f"False Negatives: {fn} ({fn / total:.2%})")
    print(f"True Positives: {tp} ({tp / total:.2%})")

    benign_false_positive_rate = fp / (fp + tn)
    attack_detection_rate = tp / (tp + fn)

    print(f"\nBenign data false positive rate: {benign_false_positive_rate:.2%}")
    print(f"Attack detection rate: {attack_detection_rate:.2%}")


if __name__ == "__main__":
    # Load and preprocess data
    df = load_and_preprocess_data('./benign_exploration_attacks.csv')

    # Build separate graphs for benign and attack data
    G_benign, G_attack = build_graphs(df)

    # Extract features from both graphs
    benign_features = extract_edge_features(G_benign)
    attack_features = extract_edge_features(G_attack)

    # Combine features and labels
    all_features = np.vstack((benign_features, attack_features))
    all_labels = np.hstack((np.zeros(len(benign_features)), np.ones(len(attack_features))))

    print(
        f"Final data for model: Total={len(all_features)}, Benign={sum(all_labels == 0)}, Attack={sum(all_labels == 1)}")

    # Ensure there are benign samples
    if sum(all_labels == 0) == 0:
        raise ValueError("No benign instances found in the dataset.")

    # Train anomaly detector on benign data
    detector = GraphAnomalyDetector(contamination=0.1)
    detector.fit(benign_features)

    # Predict on all data
    y_pred = detector.predict(all_features)
    y_pred_binary = np.where(y_pred == -1, 1, 0)

    # Print evaluation report
    print_evaluation_report(all_labels, y_pred_binary)

    # Plot confusion matrix
    plot_confusion_matrix(confusion_matrix(all_labels, y_pred_binary))