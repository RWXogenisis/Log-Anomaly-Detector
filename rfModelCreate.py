import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_score, recall_score
from joblib import dump
import argparse

def train_and_save_model(file_path: str, model_save_path: str):
    # Load the CSV file
    df = pd.read_csv(file_path)

    # Drop unnecessary datetime, sdate, and edate columns
    df = df.drop(columns=["datetime", "sdate", "edate"])

    # Separate features and target
    X = df.drop(columns=["IDS_decision"])
    y = df["IDS_decision"]

    # Separate numeric and categorical columns
    numeric_cols = X.select_dtypes(include=['number']).columns
    categorical_cols = X.select_dtypes(exclude=['number']).columns

    # Create transformers for numeric and categorical columns
    numeric_transformer = SimpleImputer(strategy='mean')
    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='most_frequent')),
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])

    # Use ColumnTransformer to apply transformers to different columns
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_cols),
            ('cat', categorical_transformer, categorical_cols)
        ])

    # Create and train a RandomForestClassifier within a pipeline
    model = Pipeline(steps=[('preprocessor', preprocessor),
                            ('classifier', RandomForestClassifier())])

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Fit the model
    model.fit(X_train, y_train)

    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # Calculate precision and recall
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')

    # Print precision and recall
    print(f"Precision: {precision}")
    print(f"Recall: {recall}")

    # Save the trained model
    dump(model, model_save_path)
    print(f"Model saved to: {model_save_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train and save a Random Forest classifier')
    parser.add_argument('--file_path', type=str, default='./server logs/test_train.csv',
                        help='Supervised set file path (default: ./server logs/test_train.csv)')
    parser.add_argument('--model_save_path', type=str, default='./log_predictor.joblib',
                        help='Model save path (default: ./log_predictor.joblib)')
    args = parser.parse_args()

    train_and_save_model(args.file_path, args.model_save_path)
