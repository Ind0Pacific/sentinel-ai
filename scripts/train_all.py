"""
SENTINEL AI — Train All Models
Convenience runner to train and benchmark all machine learning models in sequence.
"""

from common import logger
from train_phishing_model import train_phishing_model
from train_network_model import train_network_model
from train_auth_anomaly_model import train_auth_anomaly_model
from train_malware_model import train_malware_model
from evaluate_models import evaluate_all_models
from register_models import scan_and_register_all_models


def train_all():
    logger.info("Initiating sequential training for all models...")
    train_phishing_model()
    train_network_model()
    train_auth_anomaly_model()
    train_malware_model()
    evaluate_all_models()
    scan_and_register_all_models()
    logger.info("All models trained, evaluated, and registered successfully.")


if __name__ == "__main__":
    train_all()
