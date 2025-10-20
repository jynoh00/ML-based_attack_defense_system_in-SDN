#!/usr/bin/env python3

import pandas as pd
import numpy as np
import os
import argparse
import time
import joblib
import json
from datetime import datetime

# ML 부
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier

# evaluation 부
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from sklearn.model_selection import cross_val_score, GridSearchCV, StratifiedKFold

# deep-learning 부
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

import matplotlib.pyplot as plt
import seaborn as sns

import warnings
warnings.filterwarnings('ignore')

class MLTrainer: # .output_dir, .model_configs, .parap_grids
    def __init__(self, output_dir='data/models/'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.model_configs = {
            'random_forest': {
                'model': RandomForestClassifier,
                'params': {
                    'n_estimators': 100,
                    'max_depth': None,
                    'min_samples_split': 2,
                    'min_samples_leaf': 1,
                    'random_state': 42,
                    'n_jobs': -1
                }
            },
            'svm': {
                'model': SVC,
                'params': {
                    'kernel': 'rbf',
                    'C': 1.0,
                    'gamma': 'scale',
                    'probability': True,
                    'random_state': 42
                }
            },
            'neural_network': {
                'model': MLPClassifier,
                'params': {
                    'hidden_layer_sizes': (100, 50),
                    'activation': 'relu',
                    'solver': 'adam',
                    'alpha': 0.0001,
                    'batch_size': 'auto',
                    'learning_rate': 'constant',
                    'learning_rate_init': 0.001,
                    'max_iter': 200,
                    'random_state': 42
                }
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier,
                'params': {
                    'n_estimators': 100,
                    'learning_rate': 0.1,
                    'max_depth': 3,
                    'random_state': 42
                }
            },
            'logistic_regression': {
                'model': LogisticRegression,
                'params': {
                    'C': 1.0,
                    'solver': 'liblinear',
                    'random_state': 42,
                    'max_iter': 1000
                }
            },
            'decision_tree': {
                'model': DecisionTreeClassifier,
                'params': {
                    'max_depth': None,
                    'min_samples_split': 2,
                    'min_samples_leaf': 1,
                    'random_state': 42
                }
            },
            'maive_bayes': {
                'model': GaussianNB,
                'params': {}
            },
            'knn': {
                'model': KNeighborsClassifier,
                'params': {
                    'n_neighbors': 5,
                    'weights': 'uniform',
                    'algorithm': 'auto'
                }
            }
        }

        self.param_grids = {
            'random_forest': {
                'n_estimators': [50, 100, 200],
                'max_depth': [None, 10, 20, 30],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            },
            'svm': {
                'C': [0.1, 1, 10, 100],
                'gamma': ['scale', 'auto', 0.001, 0.01, 0.1, 1],
                'kernel': ['rbf', 'linear', 'poly']
            },
            'neural_network': {
                'hidden_layer_sizes': [(50,), (100,), (100, 50), (100, 50, 25)],
                'alpha': [0.0001, 0.001, 0.01],
                'learning_rate_init': [0.001, 0.01, 0.1]
            },
            'gradient_boosting': {
                'n_estimators': [50, 100, 200],
                'learning_rate': [0.01, 0.1, 0.2],
                'max_depth': [3, 5, 7]
            }
        }

    def load_data(self, data_path, dataset_name): #train, test 데이터 로드 (X, y)
        print(f'Loading {dataset_name} data from {data_path} ...')

        try:
            X_train = pd.read_csv(os.path.join(data_path, 'X_train.csv'))
            X_test = pd.read_csv(os.path.join(data_path, 'X_test.csv'))
            y_train = pd.read_csv(os.path.join(data_path, 'y_train.csv')).iloc[:, 0]
            y_test = pd.read_csv(os.path.join(data_path, 'y_test.csv')).iloc[:, 0]

            print(f'Training set: {X_train.shape}')
            print(f'Test set: {X_test.shape}')
            print(f'Class distribution - Train: {y_train.value_counts().to_dict()}')
            print(f'Class distribution - Test: {y_test.value_counts().to_dict()}')

            return X_train, X_test, y_train, y_test
        except Exception as e:
            print(f'Error loading data: {e}')
            return None, None, None, None

    def train_sklearn_model(self, model_name, X_train, y_train, hyperparameter_tuning=False):
        print(f'\nTraining {model_name} model ...')

        config = self.model_configs[model_name]

        if hyperparameter_tuning and model_name in self.param_grids:
            print('Performing hyperparameter tuning ...')

            model = config['model']()
            grid_search = GridSearchCV(
                model,
                self.param_grids[model_name],
                cv=5,
                scoring='f1',
                n_jobs=-1,
                verbose=1
            )

            start_time = time.time()
            grid_search.fit(X_train, y_train)
            training_time = time.time() - start_time

            best_model = grid_search.best_estimator_
            print(f'Best parameters: {grid_search.best_params_}')
            print(f'Best CV score: {grid_search.best_score_:.4f}')
        else:
            model = config['model'](**config['params'])

            start_time = time.time()
            model.fit(X_train, y_train)
            training_time = time.time() - start_time

            best_model = model
        
        print(f'Training completed in {training_time:.2f} seconds')

        return best_model, training_time

    def create_deep_neural_network(self, input_dim, num_classes=2): 
        model = Sequential([
            Dense(256, activation='relu', input_shape=(input_dim,)),
            BatchNormalization(),
            Dropout(0.3),

            Dense(128, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),

            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),

            Dense(32, activation='relu'),
            Dropout(0.2),

            Dense(num_classes, activation='softmax' if num_classes > 2 else 'sigmoid')
        ])

        optimizer = Adam(learning_rate=0.001)
        loss = 'sparse_categorical_crossentropy' if num_classes > 2 else 'binary_crossentropy'

        model.compile(
            optimizer=optimizer,
            loss=loss,
            metrics=['accuracy']
        )

        return model
    
    def train_deep_neural_network(self, X_train, y_train, X_val=None, y_val=None):
        print('\nTraining Deep Neural Network ...')

        num_classes = len(np.unique(y_train))
        model = self.create_deep_neural_network(X_train.shape[1], num_classes)

        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ReduceLROnPlateau(patience=5, factor=0.5)
        ]

        if X_val is None or y_val is None:
            validation_split = 0.2
            validation_data = None
        else:
            validation_split = 0
            validation_data = (X_val, y_val)
        
        start_time = time.time()

        history = model.fit(
            X_train, y_train,
            batch_size=32,
            epochs=100,
            validation_split=validation_split,
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=1
        )

        training_time = time.time() - start_time
        print(f'Training completed in {training_time:.2f} seconds')

        return model, history, training_time
    
    def create_ensemble_model(self, X_train, y_train):
        print('\nCreate ensemble model ...')

        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        svm = SVC(probability=True, random_state=42)
        gb = GradientBoostingClassifier(n_estimators=100, random_state=42)

        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf),
                ('svm', svm),
                ('gb', gb)
            ],
            voting='soft'
        )

        start_time = time.time()
        ensemble.fit(X_train, y_train)
        training_time = time.time() - start_time

        print(f'Ensemble training completed in {training_time:.2f} seconds')

        return ensemble, training_time
    
    def evaluate_model(self, model, X_test, y_test, model_name='Model'):
        print(f'\nEvaluating {model_name} ...')

        start_time = time.time()

        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)
            if y_pred_proba.shape[1] == 2: y_scores = y_pred_proba[:, 1]
            else: y_scores = np.max(y_pred_proba, axis=1)
        
        elif hasattr(model, 'predict'):
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)
                y_scores = y_pred_proba[:, 1] if y_pred_proba.shape[1] == 2 else np.max(y_pred_proba, axis=1)
            else:
                y_pred_proba = model.predict(X_test)
                if len(y_pred_proba.shape) > 1 and y_pred_proba.shape[1] > 1:
                    y_scores = np.max(y_pred_proba, axis=1)
                    y_pred = np.argmax(y_pred_proba, axis=1)
                else:
                    y_scores = y_pred_proba.flatten()
                    y_pred = (y_scores > 0.5).astype(int)
        
        if 'y_pred' not in locals(): y_pred = model.predict(X_test)

        prediction_time = time.time() - start_time

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        try:
            if len(np.unique(y_test)) == 2: roc_auc = roc_auc_score(y_test, y_scores)
            else: roc_auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', average='weighted')
        except: roc_auc = 0.0

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

        if cm.shape(2, 2): 
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        else: specificity = false_positive_rate = false_negative_rate = 0

        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
            'specificity': specificity,
            'false_positive_rate': false_positive_rate,
            'false_negative_rate': false_negative_rate,
            'prediction_time': prediction_time,
            'confusion_matrix': cm.tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }

        print(f'Accuracy: {accuracy:.4f}')
        print(f'Precision: {precision:.4f}')
        print(f'Recall: {recall:.4f}')
        print(f'F1-Score: {f1:.4f}')
        print(f'ROC AUC: {roc_auc:.4f}')
        print(f'Specificity: {specificity:.4f}')
        print(f'Prediction time: {prediction_time:.4f} seconds')
        print(f'Confusion Matrix:\n{cm}')

        return metrics, y_pred, y_scores if 'y_scores' in locals() else y_pred
    def cross_validate_model(self, model, X, y, cv_folds=5): 
        print(f'\nPreforming {cv_folds}-fold cross_validation ...')

        cv_scores = {}

        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        metrics = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted']

        for metric in metrics:
            scores = cross_val_score(model, X, y, cv=skf, scoring=metric, n_jobs=-1)
            cv_scores[metric] = {
                'scores': scores.tolist(),
                'mean': scores.mean(),
                'std': scores.std()
            }

            print(f'{metric}: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})')

        return cv_scores
    
    def plot_confusion_matrix(self, cm, model_name, output_path): 
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
        plt.title(f'Confusion Matrix - {model_name}')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    def plot_roc_curve(self, y_test, y_scores, model_name, output_path):
        if len(np.unique(y_test)) == 2:
            fpr, tpr, _ = roc_curve(y_test, y_scores)
            roc_auc = roc_auc_score(y_test, y_scores)

            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curve - {model_name}')
            plt.legend(loc='lower right')
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()            

    def plot_feature_importance(self, model, feature_names, model_name, output_path, top_n=20): 
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1][:top_n]

            plt.figure(figsize=(12, 8))
            plt.title(f'Feature Importance - {model_name}')
            plt.bar(range(top_n), importances[indices])
            plt.xticks(range(top_n), [feature_names[i] for i in indices], rotation=45, ha='right')
            plt.xlabel('Features')
            plt.ylabel('Importance')
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
        
    def save_model_results(self, model, metrics, model_name, dataset_name, training_time):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        model_dir = os.path.join(self.output_dir, f'{dataset_name}_{model_name}_{timestamp}')
        os.makedirs(model_dir, exist_ok=True)
        
        if hasattr(model, 'save'): model.save(os.path.join(model_dir, 'model.h5'))
        else: joblib.dump(model, os.path.join(model_dir, 'model.pkl'))

        results = {
            'model_name': model_name,
            'dataset_name': dataset_name,
            'timestamp': timestamp,
            'training_time': training_time,
            'metrics': metrics,
        }

        with open(os.path.join(model_dir, 'results.json'), 'w') as f: json.dump(results, f, indent=2, default=str)

        print(f'Model and results saved to: {model_dir}')
        
        return model_dir

    def compare_models(self, results_list): 
        print('\n***** Model Comparison *****')

        comparison_df = pd.DataFrame([
            {
                'Model': r['model_name'],
                'Accuracy': r['metrics']['accuracy'],
                'Precision': r['metrics']['precision'],
                'Recall': r['metrics']['recall'],
                'F1-Score': r['metrics']['f1_score'],
                'ROC AUC': r['metrics']['roc_auc'],
                'Training time': r['training_time']
            }
            for r in results_list
        ])

        print(comparison_df.round(4))

        metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()

        for i, metric in enumerate(metrics_to_plot):
            if i < len(axes):
                ax = axes[i]
                values = [r['metrics'][metric] for r in results_list]
                models = [r['model_name'] for r in results_list]

                bars = ax.bar(models, values)
                ax.set_title(f'{metric.replace("_"," ").title()}')
                ax.set_ylim(0, 1)
                ax.tick_params(axis='x', rotation=45)

                for bar, value in zip(bars, values):
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                            f'{value:.3f}', ha='center', va='bottom')
        
        if len(axes) > len(metrics_to_plot):
            ax = axes[len(metrics_to_plot)]
            times = [r['training_time'] for r in results_list]
            models = [r['model_name'] for r in results_list]

            bars = ax.bar(models, times)
            ax.set_title('Training Time (seconds)')
            ax.tick_params(axis='x', rotation=45)

            for bar, time_val in zip(bars, times):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(times)*0.01,
                        f'{time_val:.2f}s', ha='center', va='bottom')
            
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'model_comparison.png'))
        plt.close()

        return comparison_df

    def train_all_models(self, X_train, X_test, y_train, y_test, dataset_name, models_to_train=None, hyperparameter_tuning=False):
        if models_to_train is None: models_to_train = list(self.model_configs.keys()) + ['deep_neural_network', 'ensemble']

        results_list = []

        print(f'\n***** Training Models for {dataset_name} Dataset *****')

        for model_name in models_to_train:
            try:
                if model_name == 'deep_neural_network':
                    model, history, training_time = self.train_deep_neural_network(X_train, y_train)
                elif model_name == 'ensemble':
                    model, training_time = self.create_ensemble_model(X_train, y_train)
                else:
                    model, training_time = self.train_sklearn_model(model_name, X_train, y_train, hyperparameter_tuning)
                
                metrics, y_pred, y_scores = self.evaluate_model(model, X_test, y_test, model_name)

                if model_name != 'deep_neural_network':
                    cv_scores = self.cross_validate_model(model, X_train, y_train)
                    metrics['cross_validation'] = cv_scores
                
                model_dir = self.save_model_results(model, metrics, model_name, dataset_name, training_time)

                self.plot_confusion_matrix(
                    np.array(metrics['confusion_matrix']),
                    model_name,
                    os.path.join(model_dir, 'confusion_matrix.png')
                )

                if len(np.unique(y_test)) == 2:
                    self.plot_roc_curve(
                        y_test, y_scores, model_name,
                        os.path.join(model_dir, 'roc_curve.png')
                    )
                
                if hasattr(model, 'feature_importances_'):
                    self.plot_feature_importance(
                        model, X_train.columns, model_name,
                        os.path.join(model_dir, 'feature_importance.png')
                    )
                
                results_list.append({
                    'model_name': model_name,
                    'model_dir': model_dir,
                    'training_time': training_time,
                    'metrics': metrics
                })
            except Exception as e: print(f'Error training {model_name}: {e}'); continue

            if len(results_list) > 1:
                comparison_df = self.compare_models(results_list)
                comparison_df.to_csv(os.path.join(self.output_dir, f'{dataset_name}_conparison.csv'), index=False)

            return results_list

def main():
    parser = argparse.ArgumentParser(description='ML Training for Network Attack Detection')
    parser.add_argument('--dataset', choices=['cicids2017', 'nslkdd'], required=True, help='Dataset to use')
    parser.add_argument('--data-path', required=True, help='Path to preprocessed data')
    parser.add_argument('--models', nargs='+',
                        choices=['random_forest', 'svm', 'neural_network', 'gradient_boosting',
                                 'logistic_regression', 'decision_tree', 'naive_bayes', 'knn',
                                 'deep_neural_network', 'ensemble', 'all'],
                                 default=['all'], help='Models to train')
    parser.add_argument('--output-dir', default='data/models/', help='Output directory')
    parser.add_argument('----hyperparameter-tuning', action='store_true', help='Perform hyperparameter tuning')
    parser.add_argument('--cross-validation', action='store_true', help='Perform cross-validation')

    args = parser.parse_args()

    trainer = MLTrainer(args.output_dir)

    X_train, X_test, y_train, y_test = trainer.load_data(args.data_path, args.dataset)

    if X_train is None: print('Failed to load data. Exiting.'); return

    if 'all' in args.models: models_to_train = None
    else: models_to_train = args.models

    results = trainer.train_all_models(
        X_train, X_test, y_train, y_test,
        args.dataset, models_to_train,
        args.hyperparameter_tuning
    )

    print(f'\nTraining completed. Results saved to: {args.output_dir}')
    print(f'Trained {len(results)} models successfully.')

if __name__ == '__main__': main()