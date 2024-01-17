import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
from urllib.parse import unquote

# Load the vectorizer
vectorizer = joblib.load('vectorizer.pkl')

# Load the trained model
loaded_model = joblib.load('model.pkl')

# Assuming you have the same preprocessing function as loadFile
def preprocess_paths(paths):
    result = []
    for path in paths:
        path = str(unquote(path))
        result.append(path)
    return result

def load_and_predict_save(csv_path, vectorizer, loaded_model, save_path):
    # Load CSV file
    df = pd.read_csv(csv_path)

    # Assuming the column with paths is named 'resource_path', adjust if needed
    paths_column = df['resource_path'].astype(str)

    # Preprocess paths
    test_queries = preprocess_paths(paths_column)

    # Vectorize paths
    X_test = vectorizer.transform(test_queries)

    # Predict
    predictions = loaded_model.predict(X_test)

    # Add predictions to the dataframe
    df['predictions'] = predictions

    # Save the dataframe to a new CSV file
    df.to_csv(save_path, index=False)

# Example usage
csv_path_to_predict = 'server.csv'
output_csv_path = 'predictions_output.csv'
load_and_predict_save(csv_path_to_predict, vectorizer, loaded_model, output_csv_path)
