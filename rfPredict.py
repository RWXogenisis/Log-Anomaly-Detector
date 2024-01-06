import pandas as pd
from joblib import load
import argparse

def make_predictions_and_save(model_path: str, new_data_path: str = "./server logs/server.csv",
                               output_csv_path: str = "./output_predictions.csv"):
    # Load the trained model
    model = load(model_path)

    # Load the new CSV file for prediction
    new_data = pd.read_csv(new_data_path)

    # Drop unnecessary datetime, sdate, and edate columns
    new_data = new_data.drop(columns=["datetime", "sdate", "edate"])

    # Make predictions
    predictions = model.predict(new_data)

    # Add predictions to the new_data DataFrame
    new_data["Predicted_IDS_Decision"] = predictions

    # Save the results to a new CSV file
    new_data.to_csv(output_csv_path, index=False)
    print(f"Predictions saved to: {output_csv_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Make predictions using a pre-trained model')
    parser.add_argument('model_path', type=str, help='Trained model file path')
    parser.add_argument('--new_data_path', type=str, default="./server logs/server.csv",
                        help='New CSV file path for prediction (default: ./server logs/server.csv)')
    parser.add_argument('--output_csv_path', type=str, default="./output_predictions.csv",
                        help='Output CSV file path to save predictions (default: ./output_predictions.csv)')
    args = parser.parse_args()

    make_predictions_and_save(args.model_path, args.new_data_path, args.output_csv_path)
