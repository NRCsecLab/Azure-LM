import pandas as pd
import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.utils import from_networkx
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
import torch.nn.functional as F
import matplotlib.pyplot as plt
import seaborn as sns


class ImprovedGNN(torch.nn.Module):
    def __init__(self, num_node_features, num_edge_features, hidden_channels):
        super(ImprovedGNN, self).__init__()
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.edge_predictor = torch.nn.Sequential(
            torch.nn.Linear(hidden_channels * 2 + num_edge_features, hidden_channels),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_channels, 1)
        )

    def forward(self, x, edge_index, edge_attr):
        x = F.relu(self.conv1(x, edge_index))
        x = self.conv2(x, edge_index)

        # Combine node features for each edge
        edge_features = torch.cat([x[edge_index[0]], x[edge_index[1]], edge_attr], dim=1)

        return self.edge_predictor(edge_features).squeeze()


def load_and_preprocess_data(file_path):
    df = pd.read_csv(file_path)
    df['createdDateTime'] = pd.to_datetime(df['createdDateTime'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
    df = df.assign(createdDateTime=df['createdDateTime'].fillna(pd.Timestamp.now()))
    print(f"Initial data shape: {df.shape}")
    print(f"Initial benign instances: {sum(df['is_attack'] == 0)}")
    print(f"Initial attack instances: {sum(df['is_attack'] == 1)}")
    return df


def build_graph_with_features(df):
    G = nx.DiGraph()
    node_features = {}
    edge_features = {}
    node_mapping = {}  # Mapping from original labels to integer indices

    node_counter = 0
    for _, row in df.iterrows():
        source = row['userId']
        target = row['appId']
        resource = row['resourceId']

        # Add nodes if they don't exist
        for node in [source, target, resource]:
            if node not in node_mapping:
                node_mapping[node] = node_counter
                G.add_node(node_counter)
                node_features[node_counter] = [0, 0, 0]  # [in_degree, out_degree, clustering_coefficient]
                node_counter += 1

        # Add edges
        for edge in [(node_mapping[source], node_mapping[target]), (node_mapping[target], node_mapping[resource])]:
            if edge not in G.edges():
                G.add_edge(*edge)
                time = row['createdDateTime']
                edge_features[edge] = [
                    time.hour,
                    time.weekday(),
                    0,  # out_degree of source (to be updated later)
                    0,  # in_degree of target (to be updated later)
                    0,  # clustering of source (to be updated later)
                    0,  # clustering of target (to be updated later)
                    0,  # degree centrality of source (to be updated later)
                    0,  # degree centrality of target (to be updated later)
                    1,  # number of parallel edges (initially 1)
                    0,  # number of paths (to be updated later)
                    hash(row['PROTOCOL']) % 10,
                    int(row['is_attack'])
                ]
            else:
                edge_features[edge][-2] += 1  # Increment number of parallel edges

    # Update node and edge features
    for node in G.nodes():
        node_features[node][0] = G.in_degree(node)
        node_features[node][1] = G.out_degree(node)
        node_features[node][2] = nx.clustering(G, node)

    degree_centrality = nx.degree_centrality(G)

    for edge in G.edges():
        source, target = edge
        edge_features[edge][2] = G.out_degree(source)
        edge_features[edge][3] = G.in_degree(target)
        edge_features[edge][4] = node_features[source][2]
        edge_features[edge][5] = node_features[target][2]
        edge_features[edge][6] = degree_centrality[source]
        edge_features[edge][7] = degree_centrality[target]
        edge_features[edge][9] = len(list(nx.all_simple_paths(G, source, target, cutoff=2)))

    # Add features to graph
    nx.set_node_attributes(G, node_features, 'features')
    nx.set_edge_attributes(G, edge_features, 'features')

    print(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
    return G


def prepare_data_for_gnn(G):
    # Prepare node features
    node_features = np.array([G.nodes[node]['features'] for node in G.nodes()])

    # Prepare edge features and labels
    edge_features = []
    edge_labels = []
    for edge in G.edges(data=True):
        edge_features.append(edge[2]['features'][:-1])  # Exclude the label from features
        edge_labels.append(edge[2]['features'][-1])  # The label is the last element

    edge_features = np.array(edge_features)
    edge_labels = np.array(edge_labels)

    print(f"Node features shape: {node_features.shape}")
    print(f"Edge features shape: {edge_features.shape}")
    print(f"Edge labels shape: {edge_labels.shape}")

    # Normalize features
    scaler = StandardScaler()
    node_features = scaler.fit_transform(node_features)
    edge_features = scaler.fit_transform(edge_features)

    # Create PyTorch Geometric Data object
    data = from_networkx(G)
    data.x = torch.tensor(node_features, dtype=torch.float)
    data.edge_attr = torch.tensor(edge_features, dtype=torch.float)
    data.y = torch.tensor(edge_labels, dtype=torch.float)

    print(f"PyTorch Geometric Data: {data}")

    return data


def custom_loss(pred, target, mask):
    # MSE loss for benign samples
    mse_loss = F.mse_loss(pred[mask], target[mask])

    # Hinge loss for attack samples
    hinge_loss = torch.mean(torch.clamp(1 - pred[~mask] * target[~mask], min=0))

    return mse_loss + hinge_loss


def train_gnn_model(data, train_mask, epochs=100, learning_rate=0.01):
    model = ImprovedGNN(num_node_features=data.num_node_features,
                        num_edge_features=data.num_edge_features,
                        hidden_channels=64)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=5e-4)
    model.train()

    for epoch in range(epochs):
        optimizer.zero_grad()
        out = model(data.x, data.edge_index, data.edge_attr)
        loss = custom_loss(out, data.y, train_mask)
        loss.backward()
        optimizer.step()
        if epoch % 10 == 0:
            print(f'Epoch {epoch}, Loss: {loss.item()}')

    return model


def evaluate_model(model, data):
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index, data.edge_attr)
    return out.numpy()


def plot_confusion_matrix(conf_matrix):
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.show()


if __name__ == "__main__":
    df = load_and_preprocess_data('./benign_exploration_attacks.csv')

    # Build graph with all data
    G_full = build_graph_with_features(df)

    # Prepare data for GNN
    data = prepare_data_for_gnn(G_full)

    # Ensure edge_index is of type long
    data.edge_index = data.edge_index.long()

    # Create train mask (benign only) and test mask (all data)
    train_mask = data.y == 0
    test_mask = torch.ones(data.y.size(0), dtype=torch.bool)

    print(f"Training on {train_mask.sum()} benign samples")
    print(f"Testing on {test_mask.sum()} total samples")

    # Train the model on benign data only
    model = train_gnn_model(data, train_mask)

    # Evaluate the model on all data
    anomaly_scores = evaluate_model(model, data)

    # Use a threshold to convert anomaly scores to binary predictions
    threshold = np.mean(anomaly_scores) + np.std(anomaly_scores)  # Adjust this based on your data
    y_pred = (anomaly_scores > threshold).astype(int)
    y_true = data.y.numpy()

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("\nEvaluation Report:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")

    # Plot confusion matrix
    conf_matrix = confusion_matrix(y_true, y_pred)
    plot_confusion_matrix(conf_matrix)

    # Additional analysis
    tn, fp, fn, tp = conf_matrix.ravel()
    total = tn + fp + fn + tp

    print(f"\nTrue Negatives: {tn} ({tn / total:.2%})")
    print(f"False Positives: {fp} ({fp / total:.2%})")
    print(f"False Negatives: {fn} ({fn / total:.2%})")
    print(f"True Positives: {tp} ({tp / total:.2%})")

    benign_false_positive_rate = fp / (fp + tn)
    attack_detection_rate = tp / (tp + fn)

    print(f"\nBenign data false positive rate: {benign_false_positive_rate:.2%}")
    print(f"Attack detection rate: {attack_detection_rate:.2%}")

    # Try different percentiles for the threshold
    for percentile in [90, 80, 70, 60, 50]:
        threshold = np.percentile(anomaly_scores, percentile)
        y_pred = (anomaly_scores > threshold).astype(int)

        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        print(f"\nEvaluation Report (Threshold at {percentile}th percentile):")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-score: {f1:.4f}")

        # Additional analysis
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        total = tn + fp + fn + tp

        print(f"True Negatives: {tn} ({tn / total:.2%})")
        print(f"False Positives: {fp} ({fp / total:.2%})")
        print(f"False Negatives: {fn} ({fn / total:.2%})")
        print(f"True Positives: {tp} ({tp / total:.2%})")

        benign_false_positive_rate = fp / (fp + tn)
        attack_detection_rate = tp / (tp + fn)

        print(f"Benign data false positive rate: {benign_false_positive_rate:.2%}")
        print(f"Attack detection rate: {attack_detection_rate:.2%}")