# Network Intrusion Detection System (NIDS) using UNSW-NB15 Dataset

## Introduction

This repository contains the code and resources for a Network Intrusion Detection System (NIDS) developed using deep learning techniques. The system is designed to detect various types of network attacks in real-time. It leverages the UNSW-NB15 dataset for training and evaluation, and Scapy for real-time packet capture and feature extraction.

## Dataset

The UNSW-NB15 dataset was used for exploratory data analysis (EDA), training, and testing the model. The dataset includes a wide range of network traffic data, both normal and malicious. You can be found the  dataset [here](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

### Files:
- **UNSW_NB15_training-set.csv**: The training dataset containing 175341 network flow records.
- **UNSW_NB15_testing-set.csv**: The testing dataset containing 175341 network flow records.

Both the training and testing files contained 45 features. For the purpose of this project, we eliminated some features, retaining only the most important ones. The final set of 16 features used were:

- 'dur'
- 'proto'
- 'service'
- 'state'
- 'spkts'
- 'dpkts'
- 'sbytes'
- 'dbytes'
- 'rate'
- 'sttl'
- 'dttl'
- 'smean'
- 'dmean'
- 'trans_depth'
- 'response_body_len'
- 'label'
## Model Architecture Definition

### Input Layer:

The input layer receives the 13 selected features from the preprocessed dataset.
### Hidden Layers:

The network consists of multiple fully connected (dense) hidden layers.
Each hidden layer is followed by a Batch Normalization layer to stabilize and accelerate the training process.
Rectified Linear Unit (ReLU) activation functions are used to introduce non-linearity, allowing the network to learn complex patterns in the data.

### Output Layer:

The output layer consists of a single neuron with a Sigmoid activation function.
This setup is suitable for binary classification, as it outputs a probability value between 0 and 1, indicating whether the network traffic is normal or an attack.

## Model Training

The model is a deep learning neural network implemented using PyTorch. It was trained to classify network traffic as either an attack or normal. The model achieved the following results:

- **Accuracy**: 93.46%
- **Precision**: 91.24%
- **Recall**: 99.99%
- **F1 Score**: 95.42%

### Training Script

The training script preprocesses the dataset, trains the model, and evaluates its performance. Key components include:

- Data preprocessing using LabelEncoder and StandardScaler.
- Model architecture definition.
- Training loop with loss and accuracy metrics.

## Integration with NIDS

The trained model was integrated with a real-time NIDS script. This script uses Scapy to capture network packets and extract relevant features, which are then fed into the trained model to make predictions. The system prints detailed information about each prediction, including network-related details.

### NIDS Script

The NIDS script processes real-time network traffic to detect attacks. It includes:

- Feature extraction from captured packets.
- Protocol and service mapping for accurate feature representation.
- Real-time attack detection with detailed logging of prediction and network information.

## Usage

To use this repository, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/nids-using-unsw-nb15.git
    cd nids-using-unsw-nb15
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the training script**:
    ```bash
    python train_model.py
    ```

4. **Run the NIDS script**:
    ```bash
    sudo python real_time_packet_analysis.py
    ```

## Conclusion

This repository provides a comprehensive solution for network intrusion detection using deep learning. The integration of the trained model with real-time packet capture allows for effective detection of network attacks. The system's high accuracy and detailed logging make it a valuable tool for network security.

Feel free to contribute to this repository by submitting issues or pull requests. Your feedback and contributions are welcome!
