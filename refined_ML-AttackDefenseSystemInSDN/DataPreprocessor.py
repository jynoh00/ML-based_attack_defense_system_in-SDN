#!/usr/bin/env python3

# CIC-IDS 2017, NSL-KDD 데이터셋 전처리기

import pandas as pd
import numpy as np
import os
import urllib.request
import zipfile
import argparse
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

class DataPreprocessor:
    def __init__(self, dataset_path='data/datasets/', processed_path='data/processed/'):
        self.dataset_path = dataset_path
        self.processed_path = processed_path
        self.create_directories()
        
        self.cicids_config = { # config.json으로 외부화
            'files': [
                'Monday-WorkingHours.pcap_ISCX.csv',
                'Tuesday-WorkingHours.pcap_ISCX.csv', 
                'Wednesday-workingHours.pcap_ISCX.csv',
                'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
                'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
                'Friday-WorkingHours-Morning.pcap_ISCX.csv',
                'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
                'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
            ],
            'label_col': 'Label'
        }

        self.nslkdd_config = { # 이것도
            'train_file': 'KDDTrain+.txt',
            'test_file': 'KDDTest+.txt',
            'label_col': 'class'
        }
    
    def create_directories(self): # dataset_path, processed_path 경로 디렉토리 생성
        os.makedirs(self.dataset_path, exist_ok=True)
        os.makedirs(self.processed_path, exist_ok=True)

    def download_datasets(self):
        print('Downloading datasets ...')

        # CIC-IDS 2017 데이터셋은 직접
        # CIC-IDS 2017 Dataset
        # https://www.unb.ca/cic/datasets/ids-2017.html
        # Extract CSV files to: data/datasets/cicids2017/
    
        nslkdd_url = 'https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.txt'
        nslkdd_test_url = 'https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.txt'

        nslkdd_path = os.path.join(self.dataset_path, 'nslkdd') # data/datasets/nslkdd
        os.makedirs(nslkdd_path, exist_ok=True)

        try:
            urllib.request.urlretrieve(nslkdd_url, os.path.join(nslkdd_path, 'KDDTrain+.txt'))
            urllib.request.urlretrieve(nslkdd_test_url, os.path.join(nslkdd_path, 'KDDTest+.txt'))
            print('NSL-KDD downloaded done.')
        except Exception as e: print(f'Error downloading NSL-KDD: {e}')
    
    def load_cicids2017(self, sample_size=None):
        print('Loading CIC-IDS 2017 dataset ...')

        cicids_path = os.path.join(self.dataset_path, 'cicids2017')
        if not os.path.exists(cicids_path):
            print(f'CIC-IDS 2017 dataset not found at {cicids_path}')
            return None, None
        
        dfs = [] # dataframes
        for filename in self.cicids_config['files']:
            file_path = os.path.join(cicids_path, filename)
            if os.path.exists(file_path):
                try:
                    df = pd.read_csv(file_path, encoding='utf-8')
                    
                    if sample_size and len(df) > sample_size:
                        df = df.sample(n=sample_size, random_state=42)
                    
                    dfs.append(df)
                    print(f'Loaded {filename}: {len(df)} records')
                except Exception as e: print(f'Error loading {filename}: {e}')
        
        if not dfs:
            print('No CIC-IDS 2017 files found')
            return None, None

        combined_df = pd.concat(dfs, ignore_index=True)
        print(f'Total CIC-IDS 2017 records: {len(combined_df)}')

        X = combined_df.drop(columns=[self.cicids_config['label_col']])
        y = combined_df[self.cicids_config['label_col']]

        return X, y
    
    def load_nslkdd(self, sample_size=None):
        print('Loading NSL-KDD dataset ...')

        nslkdd_path = os.path.join(self.dataset_path, 'nslkdd')
        train_file = os.path.join(nslkdd_path, self.nslkdd_config['train_file'])
        test_file = os.path.join(nslkdd_path, self.nslkdd_config['test_file'])

        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty'
        ]

        try:
            train_df = pd.read_csv(train_file, names=column_names, header=None)
            
            if sample_size and len(train_df) > sample_size:
                train_df = train_df.sample(n=sample_size, random_state=42)
            
            test_df = pd.read_csv(test_file, names=column_names, header=None) # validation data 아님 최종 test data
            combined_df = pd.concat([train_df, test_df], ignore_index=True)
            combined_df = combined_df.drop(columns=['difficulty'])

            print(f'NSL-KDD records: {len(combined_df)}')

            X = combined_df.drop(columns=[self.nslkdd_config['label_col']])
            y = combined_df[self.nslkdd_config['label_col']]

            return X, y
        except Exception as e:
            print(f'Error loading NSL-KDD dataset: {e}')
            return None, None
        
    def clean_cicids_data(self, X, y): # CIC-IDS 2017 데이터셋 정제 부
        print('Cleaning CIC-IDS 2017 dataset ...')

        X = X.replace([np.inf, -np.inf], np.nan) # 데이터셋 X에서 무한대 값을 NaN으로 변경
        

        before_count = len(X)
        mask = ~(X.isna().any(axis=1) | y.isna()) 
        # X.isna()하면 X Dataframe에서 NaN인 부분에 True 아니면 False가 담긴 행렬을 반환
        # 이후 반환된 행렬.any(axis=1)은 그 행렬에서 모든 axis=1(행:row)을 확인 True가 하나라도 있으면 True 아니면 False인 불리언 Series 생성
        # y.isna()는 y Dataframe이 애초에 1차원 배열이기에 True False 불리언 Series 생성
        # 두 불리언 시리즈를 OR 연산 -> NaN이 하나라도 있는 행은 True (X, y 전체에서)
        # 이후 ~ not 여집합으로 기존 NaN이 있던 True 부분이 False로 바뀜
        X = X[mask]; y = y[mask]
        # pandas에 있는 boolean indexing 기능 dataframe에 boolean series를 인덱스로 넣으면 False인 행은 제거되며 새로운 행렬이 됨.
        
        print(f'Removed {before_count - len(X)} rows with missing/inf values')

        before_count = len(X)
        combined = pd.concat([X,y], axis=1) # pd.concat()으로 두 dataframe을 axis=1 즉 가로로 열을 추가하여 새로운 dataframe을 리턴
        combined = combined.drop_duplicates() # 중복된 행 제거
        X = combined.iloc[:, :-1] # iloc[]으로 행렬에서 선택(인덱싱), : -> 처음부터 끝까지 모든 행, :-1 처음부터 -1전까지 모든 열, -1은 마지막 원소 인덱스
        y = combined.iloc[:, -1] # 마지막 열의 모든 행

        print(f'Removed {before_count - len(X)} duplicate rows')

        numeric_columns = X.select_dtypes(include=[np.number]).columns # X의 열 중 데이터 타입 숫자로만 이루어진 열들로 행렬(dataframe)을 생성
                                                                        # 이후 .columns으로 해당 dataframe의 열 이름들을 추출
        for col in numeric_columns: X[col] = pd.to_numeric(X[col], errors='coerce') # column key값으로 X를 순회하며 숫자가 아닌 값은 NaN으로 변경
                                                                        # 이미 숫자로만 이루어진 열을 뽑았는데 또 이러는 이유는? -> int형 데이터타입일 경우 NaN으로 변경 x
                                                                        # 추후 바꿀 가능성 고려 일관적으로 전체 숫자를 to_numeric으로 float형으로 관리

        categorical_columns = X.select_dtypes(exclude=[np.number]).columns # 숫자가 아닌 열 선택
        for col in categorical_columns: X[col] = X[col].astype(str).str.strip() # string타입(문자열)으로 변환하고 strip()로 좌우 공백 제거

        return X, y


    def clean_nslkdd_data(self, X, y): # NSL-KDD 데이터셋 정제 부
        print('Cleaning NSL-KDD dataset ...')

        before_count = len(X)
        mask = ~(X.isna().any(axis=1) | y.isna())
        X = X[mask]; y = y[mask]
        
        print(f'Removed {before_count - len(X)} rows with missing values')

        before_count = len(X)
        combined = pd.concat([X, y], axis=1)
        combined = combined.drop_duplicates()
        X = combined.iloc[:, :-1]
        y = combined.iloc[:, -1]
        
        print(f'Removed {before_count - len(X)} duplicate rows')

        return X, y

    def encode_features(self, X_train, X_test=None):
        print('Encoding categorical features ...')

        categorical_columns = X_train.select_dtypes(exclude=[np.number]).columns
        encoders = {}

        for col in categorical_columns:
            encoder = LabelEncoder()
            X_train[col] = encoder.fit_transform(X_train[col].astype(str))
            encoders[col] = encoder

            if X_test is not None:
                X_test_col = X_test[col].astype(str)
                mask = X_test_col.isin(encoder.classes_)
                X_test.loc[mask, col] = encoder.transform(X_test_col[mask])
                X_test.loc[~mask, col] = -1
            
        return X_train, X_test, encoders

    def normalize_features(self, X_train, X_test=None, method='standard'): # features 데이터 정규화
        print(f'Normalizing features using {method} scaling ...')

        if method == 'standard': scaler = StandardScaler() # 표준화, 평균 0, 분산 1
        elif method == 'minmax': scaler = MinMaxScaler() # 최소-최대 스케일링 (0~1 범위로 압축)
        else: raise ValueError('Method must be "standard" or "minmax"')

        X_train_scaled = scaler.fit_transform(X_train)
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns, index=X_train.index)
        
        if X_test is not None:
            X_test_scaled = scaler.transform(X_test)
            X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns, index=X_test.index)
        else: X_test_scaled = None

        return X_train_scaled, X_test_scaled, scaler
        
    def create_binary_labels(self, y, dataset_type='cicids'):
        print('Creating binary labels ...')

        if dataset_type == 'cicids': binary_labels = y.apply(lambda x: 0 if x == 'BENIGN' else 1)
        elif dataset_type == 'nslkdd': binary_labels = y.apply(lambda x: 0 if x == 'normal' else 1)
        else: raise ValueError('dataset_type must be "cicids" or "nslkdd"')

        return binary_labels

    def process_dataset(self, dataset_name, sample_size=None, binary=True, test_size=0.2, scaling='standard'):
        print(f'\n***** Processing {dataset_name} Dataset *****')

        if dataset_name.lower() == 'cicids2017':
            X, y = self.load_cicids2017(sample_size)
            if X is None: return None
            X, y = self.clean_cicids_data(X, y)
            if binary: y = self.create_binary_labels(y, 'cicids')

        elif dataset_name.lower() == 'nslkdd':
            X, y = self.load_nslkdd(sample_size)
            if X is None: return None
            X, y = self.clean_nslkdd_data(X, y)
            if binary: y = self.create_binary_labels(y, 'nslkdd')
        
        else: raise ValueError('Dataset must be "cicids2017" or "nslkdd"')

        # dataset 내부 데이터 분리
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        # categorical features encoding
        X_train, X_test, encoders = self.encode_features(X_train, X_test)
        # features 정규화 (기본 - 표준화)
        X_train, X_test, scaler = self.normalize_features(X_train, X_test, scaling)

        # processed data 저장 
        output_path = os.path.join(self.processed_path, dataset_name.lower())
        os.makedirs(output_path, exist_ok=True)

        X_train.to_csv(os.path.join(output_path, 'X_train.csv'), index=False)
        X_test.to_csv(os.path.join(output_path, 'X_test.csv'), index=False)
        y_train.to_csv(os.path.join(output_path, 'y_train.csv'), index=False)
        y_test.to_csv(os.path.join(output_path, 'y_test.csv'), index=False)

        # 전처리기 저장
        import joblib
        joblib.dump(encoders, os.path.join(output_path, 'encoders.pkl'))
        joblib.dump(scaler, os.path.join(output_path, 'scaler.pkl'))

        print(f'Processed dataset saved to {output_path}')
        print(f'Training set: {X_train.shape}')
        print(f'Test set: {X_test.shape}')

        return {
            'X_train': X_train, 'X_test': X_test,
            'y_train': y_train, 'y_test': y_test,
            'encoders': encoders, 'scaler': scaler
        }

def main():
    parser = argparse.ArgumentParser(description='Data Preprocessing for ML-based Attack-Defense System in SDN')
    
    parser.add_argument('--dataset', choices=['cicids2017', 'nslkdd', 'both'])
    parser.add_argument('--sample-size', type=int, default=None, help='Sample size for large datasets')
    parser.add_argument('--binary', action='store_true', default=True, help='Create binary labels (normal, attack)')
    parser.add_argument('--download', action='store_true', help='Download datasets')
    parser.add_argument('--scaling', choices=['standard', 'minmax'], default='standard', help='Feature scaling method')

    args = parser.parse_args()

    preprocessor = DataPreprocessor()

    if args.download: preprocessor.download_datasets()
    
    if args.dataset in ['cicids2017', 'both']:
        result = preprocessor.process_dataset('cicids2017', args.sample_size, args.binary, scaling=args.scaling)
        if result: print('CIC-IDS 2017 preprocessing completed successfully')

    if args.dataset in ['nslkdd', 'both']:
        result = preprocessor.process_dataset('nslkdd', args.sample_size, args.binary, scaling=args.scaling)
        if result: print('NSL-KDD preprocessing completed successfully')

if __name__ == '__main__': main()